using System;
using System.Drawing;
using System.IO;
using System.Windows;
using System.Windows.Forms;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Security.RealTime;
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
        private readonly IScanCoordinatorService? _scanCoordinator;
        private readonly IBackgroundProtectionService? _protectionService;
        private ToolStripMenuItem? _statusMenuItem;
        private bool _isDisposed;

        public SystemTrayService(
            IScanCoordinatorService? scanCoordinator = null,
            IBackgroundProtectionService? protectionService = null)
        {
            _scanCoordinator = scanCoordinator;
            _protectionService = protectionService;
        }

        public void Initialize()
        {
            if (_notifyIcon != null) return;

            _notifyIcon = new NotifyIcon();

            // Load app icon
            try
            {
                var iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "Images", "app.ico");
                if (File.Exists(iconPath))
                {
                    _notifyIcon.Icon = new Icon(iconPath);
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

            _notifyIcon.Text = "Ultron Defender Total Security - Sistem Korumada";
            _notifyIcon.Visible = true;

            // Context Menu
            var contextMenu = new ContextMenuStrip();

            var openItem = new ToolStripMenuItem("Ultron Defender'ı Aç", null, (s, e) => RestoreMainWindow());
            openItem.Font = new Font(openItem.Font, System.Drawing.FontStyle.Bold);
            contextMenu.Items.Add(openItem);

            contextMenu.Items.Add(new ToolStripSeparator());

            _statusMenuItem = new ToolStripMenuItem("🛡️ Koruma Durumu: Aktif", null, (s, e) => { });
            _statusMenuItem.Enabled = false;
            contextMenu.Items.Add(_statusMenuItem);

            var scanItem = new ToolStripMenuItem("🔍 Hızlı Tarama Başlat", null, (s, e) =>
            {
                RestoreMainWindow();
                _ = _scanCoordinator?.StartScanAsync(ScanType.Quick);
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

        public void ShowNotification(string title, string message, ToolTipIcon icon = ToolTipIcon.Info)
        {
            _notifyIcon?.ShowBalloonTip(4000, title, message, icon);
        }

        public void UpdateProtectionStatus(bool isProtected)
        {
            if (_notifyIcon != null)
            {
                _notifyIcon.Text = isProtected 
                    ? "Ultron Defender - Sistem Korumada" 
                    : "Ultron Defender - UYARI: Koruma Devre Dışı";

                if (_statusMenuItem != null)
                {
                    _statusMenuItem.Text = isProtected 
                        ? "🛡️ Koruma Durumu: Aktif" 
                        : "⚠️ Koruma Durumu: Devre Dışı";
                }
            }
        }

        public void Dispose()
        {
            if (_isDisposed) return;
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
