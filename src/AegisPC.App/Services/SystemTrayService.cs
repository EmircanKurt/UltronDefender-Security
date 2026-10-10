using System;
using System.Drawing;
using System.IO;
using System.Windows;
using System.Windows.Forms;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using AegisPC.Security.RealTime;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;
using Microsoft.Extensions.DependencyInjection;
using Application = System.Windows.Application;

namespace AegisPC.App.Services
{
    public interface ISystemTrayService : IDisposable
    {
        void Initialize();
        void ShowNotification(string title, string message, ToolTipIcon icon = ToolTipIcon.Info);
        void UpdateProtectionStatus(bool isProtected);
    }

    public class SystemTrayService : ISystemTrayService
    {
        private NotifyIcon? _notifyIcon;
        private readonly IBackgroundProtectionService? _protectionService;
        private ToolStripMenuItem? _statusMenuItem;
        private bool _isDisposed;
        private readonly IServiceIpcClient? _ipc;
        private readonly TrayProtectionActions? _trayActions;
        private ProtectionStatus? _lastStatus;

        public SystemTrayService(
            IScanCoordinatorService? scanCoordinator = null,
            IBackgroundProtectionService? protectionService = null,
            IServiceIpcClient? ipc = null,
            IProtectionDisableConfirmation? confirmation = null)
        {
            _protectionService = protectionService;
            _ipc = ipc;
            if (ipc != null && confirmation != null) _trayActions = new TrayProtectionActions(ipc, confirmation);
        }

        public void Initialize()
        {
            if (_notifyIcon != null) return;

            _notifyIcon = new NotifyIcon();

            // Load app icon with multiple fallbacks
            try
            {
                var iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "Images", "app.ico");
                var altIconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "Images", "ultron_shield.ico");
                var rootIconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app.ico");

                Icon? loadedIcon = null;

                if (File.Exists(iconPath))
                {
                    loadedIcon = new Icon(iconPath);
                }
                else if (File.Exists(altIconPath))
                {
                    loadedIcon = new Icon(altIconPath);
                }
                else if (File.Exists(rootIconPath))
                {
                    loadedIcon = new Icon(rootIconPath);
                }
                else
                {
                    var streamInfo = Application.GetResourceStream(new Uri("pack://application:,,,/Resources/Images/app.ico"));
                    if (streamInfo != null)
                    {
                        loadedIcon = new Icon(streamInfo.Stream);
                    }
                }

                if (loadedIcon != null)
                {
                    _notifyIcon.Icon = new Icon(loadedIcon, SystemInformation.SmallIconSize);
                }
                else
                {
                    _notifyIcon.Icon = SystemIcons.Shield;
                }
            }
            catch
            {
                _notifyIcon.Icon = SystemIcons.Shield;
            }

            _notifyIcon.Text = "Ultron Defender - Koruma durumu bekleniyor";
            _notifyIcon.Visible = true;

            // Context Menu
            var contextMenu = new ContextMenuStrip();

            var openItem = new ToolStripMenuItem("Ultron Defender'ı Aç", null, (s, e) => RestoreMainWindow());
            openItem.Font = new Font(openItem.Font, System.Drawing.FontStyle.Bold);
            contextMenu.Items.Add(openItem);

            contextMenu.Items.Add(new ToolStripSeparator());

            _statusMenuItem = new ToolStripMenuItem("Koruma durumu bekleniyor", null, (s, e) => { });
            _statusMenuItem.Enabled = false;
            contextMenu.Items.Add(_statusMenuItem);
            var manage = new ToolStripMenuItem("Korumaları yönet");
            manage.DropDownItems.Add(new ToolStripMenuItem("Kalkan ayarlarını aç", null, (s, e) =>
            {
                RestoreMainWindow();
                MainWindow.Instance?.NavigateTo(typeof(AegisPC.App.Views.UltronProtectionCentreView));
            }));
            manage.DropDownItems.Add(new ToolStripSeparator());
            manage.DropDownItems.Add(new ToolStripMenuItem("Dosya kalkanını yeniden aç", null,
                async (s, e) => await ExecuteTrayControlAsync(() => _trayActions!.ResumeAsync(), "Dosya kalkanı hizmette yeniden açıldı.")) { Enabled = _trayActions != null });
            var pauseMenu = new ToolStripMenuItem("Dosya kalkanını duraklat") { Enabled = _trayActions != null };
            foreach (var option in new[] { (10, "10 dakika"), (60, "1 saat"), (300, "5 saat") })
            {
                int minutes = option.Item1;
                pauseMenu.DropDownItems.Add(new ToolStripMenuItem(option.Item2, null, async (s, e) =>
                    await ExecuteTrayControlAsync(async () =>
                    {
                        if (await _trayActions!.PauseAsync(minutes)) ShowNotification("Dosya kalkanı duraklatıldı", "Süreli geri açma isteği koruma hizmetine kaydedildi.", ToolTipIcon.Warning);
                    })));
            }
            pauseMenu.DropDownItems.Add(new ToolStripMenuItem("Koruma hizmeti yeniden başlayana kadar", null, async (s, e) =>
                await ExecuteTrayControlAsync(async () =>
                {
                    if (await _trayActions!.PauseAsync(0, true)) ShowNotification("Dosya kalkanı duraklatıldı", "Koruma hizmetinin sonraki başlangıcında geri açılacak.", ToolTipIcon.Warning);
                })));
            manage.DropDownItems.Add(pauseMenu);
            manage.DropDownItems.Add(new ToolStripMenuItem("Diğer kalkanlar değişmez") { Enabled = false });
            contextMenu.Items.Add(manage);
            contextMenu.Opening += (s, e) => UpdateProtectionStatus(false);
            if (_ipc != null) _ipc.StatusChanged += OnServiceStatusChanged;

            var scanItem = new ToolStripMenuItem("🔍 Hızlı Tarama Başlat", null, async (s, e) =>
            {
                try
                {
                    var dispatcher = Application.Current?.Dispatcher
                        ?? throw new InvalidOperationException("Application dispatcher is unavailable.");
                    await dispatcher.InvokeAsync(async () =>
                    {
                        RestoreMainWindow();
                        var scanVm = App.ServiceProvider?.GetService<ScanViewModel>()
                            ?? throw new InvalidOperationException("Scan view model is unavailable.");
                        await scanVm.StartQuickScanAsync();
                    }).Task.Unwrap();
                }
                catch (Exception ex)
                {
                    Serilog.Log.Warning(ex, "Tray quick scan request failed");
                    ShowNotification("Tarama başlatılamadı", "Tarayıcı hazır değil. Uygulamayı açıp tekrar deneyin.", ToolTipIcon.Warning);
                }
            });
            contextMenu.Items.Add(scanItem);

            contextMenu.Items.Add(new ToolStripSeparator());

            var exitItem = new ToolStripMenuItem("Çıkış", null, (s, e) =>
            {
                MainWindow.AllowClose = true;
                _notifyIcon.Visible = false;
                Application.Current.Shutdown();
            });
            contextMenu.Items.Add(exitItem);

            _notifyIcon.ContextMenuStrip = contextMenu;
            _notifyIcon.DoubleClick += (s, e) => RestoreMainWindow();
        }

        private void RestoreMainWindow()
        {
            if (MainWindow.Instance != null)
            {
                MainWindow.Instance.ShowAndActivate();
            }
            else
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    App.IsStartMinimized = false;
                    var mainWindow = Application.Current.MainWindow;
                    if (mainWindow != null)
                    {
                        if (mainWindow.WindowState == WindowState.Minimized)
                        {
                            mainWindow.WindowState = WindowState.Normal;
                        }
                        mainWindow.Show();
                        mainWindow.Activate();
                        mainWindow.Focus();
                    }
                });
            }
        }

        private void OnServiceStatusChanged(ProtectionStatus status)
        {
            var dispatcher = Application.Current?.Dispatcher;
            if (dispatcher == null || dispatcher.HasShutdownStarted || _isDisposed) return;
            dispatcher.BeginInvoke(() =>
            {
                if (_isDisposed) return;
                _lastStatus = status;
                UpdateProtectionStatus(status.IsRealTimeEnabled);
            });
        }

        private async System.Threading.Tasks.Task ExecuteTrayControlAsync(Func<System.Threading.Tasks.Task> action, string? success = null)
        {
            try
            {
                if (_trayActions == null) throw new InvalidOperationException("Koruma hizmeti hazır değil.");
                await action();
                if (success != null) ShowNotification("Ultron Defender", success);
            }
            catch (Exception exception)
            {
                Serilog.Log.Warning(exception, "Tray protection control was not confirmed");
                ShowNotification("Koruma işlemi doğrulanmadı", exception.Message, ToolTipIcon.Warning);
            }
        }

        public void ShowNotification(string title, string message, ToolTipIcon icon = ToolTipIcon.Info)
        {
            _notifyIcon?.ShowBalloonTip(4000, title, message, icon);
        }

        public void UpdateProtectionStatus(bool isProtected)
        {
            if (_notifyIcon != null)
            {
                bool observed = ServiceProtectionStatusPolicy.IsVerified(_ipc, _lastStatus);
                string text = !observed ? "Dosya kalkanı: Durum alınamadı"
                    : _lastStatus!.IsRealTimeEnabled ? "Dosya kalkanı: Gözlem etkin"
                    : _lastStatus.FileProtectionPause?.ResumeAtUtc is DateTime until ? $"Dosya kalkanı: {until.ToLocalTime():HH:mm} için geri açma planlı"
                    : _lastStatus.FileProtectionPause?.ResumeOnServiceStart == true ? "Dosya kalkanı: Hizmet başlangıcında geri açma planlı"
                    : "Dosya kalkanı: Kapalı";
                _notifyIcon.Text = "Ultron Defender - " + (observed && _lastStatus!.IsRealTimeEnabled ? "Dosya gözlemi etkin" : "Kalkan durumunu kontrol et");

                if (_statusMenuItem != null)
                {
                    _statusMenuItem.Text = text;
                }
            }
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            if (_ipc != null) _ipc.StatusChanged -= OnServiceStatusChanged;
            if (_notifyIcon != null)
            {
                _notifyIcon.Visible = false;
                _notifyIcon.Dispose();
                _notifyIcon = null;
            }
            _isDisposed = true;
        }
    }
}
