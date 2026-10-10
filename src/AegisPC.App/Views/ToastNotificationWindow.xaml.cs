using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.DependencyInjection;

namespace AegisPC.App.Views
{
    /// <summary>Presents a compact, nonactivating notification; severity never proves containment.</summary>
    public partial class ToastNotificationWindow : Window
    {
        private System.Windows.Threading.DispatcherTimer? _closeTimer;
        private static ToastNotificationWindow? _activeToast;
        private static readonly object _toastLock = new();
        private string _currentType = "Info";

        /// <summary>Overrides the details destination when supplied by the producer.</summary>
        public Type? CustomTargetPage { get; set; }
        /// <summary>Runs the producer's optional details action after navigation.</summary>
        public Action? CustomClickAction { get; set; }

        /// <summary>Initializes presentation without starting protection engines.</summary>
        public ToastNotificationWindow()
        {
            InitializeComponent();
        }

        /// <summary>Shows or updates one notification on the UI dispatcher, respecting notification settings.</summary>
        public static void ShowToast(string title, string message, string type = "Info", Type? targetPageType = null, Action? clickAction = null)
        {
            try
            {
                if (App.ServiceProvider != null)
                {
                    var settings = App.ServiceProvider.GetService<ISettingsService>();
                    if (settings != null && !settings.GetSetting("NotificationsEnabled", true))
                    {
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Bildirim ayarı kontrol edilirken hata oluştu.");
            }

            Application.Current?.Dispatcher?.Invoke(() =>
            {
                try
                {
                    lock (_toastLock)
                    {
                        if (_activeToast != null && _activeToast.IsLoaded)
                        {
                            _activeToast.CustomTargetPage = targetPageType;
                            _activeToast.CustomClickAction = clickAction;
                            _activeToast.UpdateContent(title, message, type);
                            return;
                        }

                        var toast = new ToastNotificationWindow();
                        _activeToast = toast;
                        toast.CustomTargetPage = targetPageType;
                        toast.CustomClickAction = clickAction;
                        toast.Closed += (s, e) =>
                        {
                            lock (_toastLock)
                            {
                                if (_activeToast == toast) _activeToast = null;
                            }
                        };
                        toast.Setup(title, message, type);
                        toast.Show();
                    }
                }
                catch (Exception ex)
                {
                    Serilog.Log.Error(ex, "Toast penceresi açılırken hata oluştu.");
                }
            });
        }

        /// <summary>Replaces source details without movement or pulsing and restarts the reading timeout.</summary>
        public void UpdateContent(string title, string message, string type)
        {
            _currentType = type;
            ToastTitle.Text = CleanTitle(title);
            ToastMessage.Text = message;
            ApplyStyling(type);

            _closeTimer?.Stop();
            if (_closeTimer != null) _closeTimer.Interval = TimeSpan.FromSeconds(10);
            _closeTimer?.Start();
        }

        private void Setup(string title, string message, string type)
        {
            _currentType = type;
            ToastTitle.Text = CleanTitle(title);
            ToastMessage.Text = message;

            // Ekranın sağ alt köşesine konumlandır (çalışma alanı referanslı)
            var workArea = SystemParameters.WorkArea;
            Left = workArea.Right - Width - 16;
            Top = workArea.Bottom - Height - 16;

            ApplyStyling(type);

            // Quiet appearance; hovering pauses the reading timeout.
            _closeTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
            _closeTimer.Tick += (s, e) => CloseToast();
            _closeTimer.Start();
        }

        /// <summary>Removes decorative symbols without inferring a detection or a successful security action.</summary>
        public static string CleanTitle(string title)
        {
            if (string.IsNullOrWhiteSpace(title)) return "Ultron Defender bildirimi";
            var cleaned = title.Replace("🚨", "").Replace("🛡️", "").Replace("⚠️", "").Trim();
            return string.IsNullOrWhiteSpace(cleaned) ? "Ultron Defender bildirimi" : cleaned;
        }

        private void ApplyStyling(string type)
        {
            var color = type.Equals("Error", StringComparison.OrdinalIgnoreCase) || type.Equals("Danger", StringComparison.OrdinalIgnoreCase)
                ? Color.FromRgb(190, 105, 105)
                : type.Equals("Warning", StringComparison.OrdinalIgnoreCase)
                    ? Color.FromRgb(188, 153, 98)
                    : type.Equals("Success", StringComparison.OrdinalIgnoreCase)
                        ? Color.FromRgb(108, 151, 129)
                        : Color.FromRgb(114, 151, 173);
            AccentStripe.Background = new SolidColorBrush(color);
        }

        private void CloseToast()
        {
            _closeTimer?.Stop();

            // 150ms fade-out animasyonu ile kapanış
            var fadeOut = new DoubleAnimation(Opacity, 0, TimeSpan.FromMilliseconds(150));
            fadeOut.Completed += (s, e) =>
            {
                try
                {
                    Close();
                }
                catch (Exception ex)
                {
                    Serilog.Log.Warning(ex, "Toast penceresi kapatılırken hata.");
                }
            };
            BeginAnimation(OpacityProperty, fadeOut);
        }

        private void OnCardMouseEnter(object sender, MouseEventArgs e)
        {
            // Kullanıcı bildirimin üzerine geldiğinde zamanlayıcıları ve nabzı durdur
            _closeTimer?.Stop();
        }

        private void OnCardMouseLeave(object sender, MouseEventArgs e)
        {
            if (_closeTimer != null)
            {
                _closeTimer.Interval = TimeSpan.FromSeconds(3);
                _closeTimer.Start();
            }
        }

        private void OnFooterActionClicked(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            NavigateAndClose();
        }

        private void NavigateAndClose()
        {
            try
            {
                var mainWindow = Application.Current?.MainWindow as MainWindow ?? MainWindow.Instance;
                if (mainWindow != null)
                {
                    mainWindow.ShowAndActivate();

                    Type target = CustomTargetPage ?? ResolveTargetPage(ToastTitle.Text, ToastMessage.Text, _currentType);
                    if (target != null)
                    {
                        if (target == typeof(IncidentCenterView))
                        {
                            mainWindow.NavigateToQuarantine(showIncidentsTab: true);
                        }
                        else if (target == typeof(QuarantineView))
                        {
                            mainWindow.NavigateToQuarantine(showIncidentsTab: false);
                        }
                        else
                        {
                            mainWindow.NavigateTo(target);
                        }
                    }
                }
                else if (Application.Current?.MainWindow != null)
                {
                    var mw = Application.Current.MainWindow;
                    if (mw.WindowState == WindowState.Minimized) mw.WindowState = WindowState.Normal;
                    mw.Show();
                    mw.Topmost = true;
                    mw.Activate();
                    mw.Focus();
                    mw.Topmost = false;
                }

                CustomClickAction?.Invoke();
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Toast tıklama yönlendirme hatası.");
            }
            CloseToast();
        }

        internal static Type ResolveTargetPage(string? title, string? message, string? type)
        {
            string combined = $"{title} {message}".ToLowerInvariant();

            if (combined.Contains("tarayıcı") || combined.Contains("browser") || combined.Contains("dns") || combined.Contains("web"))
            {
                return typeof(BrowserSecurityView);
            }

            if (combined.Contains("tarama") || combined.Contains("scan"))
            {
                return typeof(ScanView);
            }

            if (combined.Contains("süreç") || combined.Contains("process"))
            {
                return typeof(ProcessListView);
            }

            if (combined.Contains("çökme") || combined.Contains("crash"))
            {
                return typeof(CrashAnalysisView);
            }

            // Uyarı veya Şüpheli bildirimler doğrudan Olay Merkezi (IncidentCenterView)'ne yönlendirilir
            if (string.Equals(type, "Warning", StringComparison.OrdinalIgnoreCase) ||
                combined.Contains("şüpheli") ||
                combined.Contains("uyarıldı") ||
                combined.Contains("uyarı") ||
                combined.Contains("olay merkezi") ||
                combined.Contains("olay geçmişi"))
            {
                return typeof(IncidentCenterView);
            }

            // Tehditler, Karantina, Fidye veya Tehlike bildirimleri Karantina sayfasına yönlendirir
            if (combined.Contains("karantina") || 
                combined.Contains("tehdit") || 
                combined.Contains("zararlı") || 
                combined.Contains("threat") || 
                combined.Contains("virüs") || 
                combined.Contains("kilitlendi") || 
                combined.Contains("engellendi") || 
                combined.Contains("etkisiz") ||
                combined.Contains("fidye") ||
                combined.Contains("ransomware") ||
                string.Equals(type, "Danger", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(type, "Error", StringComparison.OrdinalIgnoreCase))
            {
                return typeof(QuarantineView);
            }

            return typeof(QuarantineView);
        }

        private void OnCloseClicked(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            CloseToast();
        }
    }
}
