using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Wpf.Ui.Controls;

namespace AegisPC.App.Views
{
    public partial class ToastNotificationWindow : Window
    {
        private System.Windows.Threading.DispatcherTimer? _closeTimer;
        private static ToastNotificationWindow? _activeToast;
        private static readonly object _toastLock = new();

        public ToastNotificationWindow()
        {
            InitializeComponent();
        }

        public static void ShowToast(string title, string message, string type = "Info")
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                try
                {
                    lock (_toastLock)
                    {
                        if (_activeToast != null && _activeToast.IsLoaded)
                        {
                            _activeToast.UpdateContent(title, message, type);
                            return;
                        }

                        var toast = new ToastNotificationWindow();
                        _activeToast = toast;
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
                catch { }
            });
        }

        public void UpdateContent(string title, string message, string type)
        {
            ToastTitle.Text = CleanTitle(title);
            ToastMessage.Text = message;
            ApplyStyling(type);
            _closeTimer?.Stop();
            _closeTimer?.Start();
        }

        private void Setup(string title, string message, string type)
        {
            ToastTitle.Text = CleanTitle(title);
            ToastMessage.Text = message;

            var workArea = SystemParameters.WorkArea;
            Left = workArea.Right - Width - 16;
            Top = workArea.Bottom - Height - 16;

            ApplyStyling(type);

            Opacity = 0;
            var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(250));
            BeginAnimation(OpacityProperty, fadeIn);

            _closeTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(6)
            };
            _closeTimer.Tick += (s, e) => CloseToast();
            _closeTimer.Start();
        }

        private static string CleanTitle(string title)
        {
            if (string.IsNullOrWhiteSpace(title)) return "Tehdit engellendi";
            return title.Replace("🚨", "").Replace("🛡️", "").Replace("⚠️", "").Trim();
        }

        private void ApplyStyling(string type)
        {
            bool isDark = AegisPC.App.Services.AppThemeManager.IsDarkMode;

            // Card Container Theme Colors
            if (isDark)
            {
                CardBorder.Background = new SolidColorBrush(Color.FromRgb(13, 27, 42)); // Deep Dark Obsidian (#0D1B2A)
                CardBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(30, 41, 59));
                ToastMessage.Foreground = new SolidColorBrush(Color.FromRgb(203, 213, 225));
                if (AppHeaderTitle != null) AppHeaderTitle.Foreground = new SolidColorBrush(Color.FromRgb(248, 250, 252));
            }
            else
            {
                CardBorder.Background = new SolidColorBrush(Color.FromRgb(255, 255, 255));
                CardBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(226, 232, 240));
                ToastMessage.Foreground = new SolidColorBrush(Color.FromRgb(71, 85, 105));
                if (AppHeaderTitle != null) AppHeaderTitle.Foreground = new SolidColorBrush(Color.FromRgb(15, 23, 42));
            }

            if (type.Equals("Warning", StringComparison.OrdinalIgnoreCase) || 
                type.Equals("Error", StringComparison.OrdinalIgnoreCase) || 
                type.Equals("Danger", StringComparison.OrdinalIgnoreCase))
            {
                AccentStripe.Background = new SolidColorBrush(Color.FromRgb(239, 68, 68)); // Red
                ToastTitle.Foreground = new SolidColorBrush(Color.FromRgb(239, 68, 68));
                BadgeIcon.Foreground = new SolidColorBrush(Color.FromRgb(239, 68, 68));
                BadgeIcon.Symbol = SymbolRegular.Warning24;
                IconBadge.Background = new SolidColorBrush(isDark ? Color.FromRgb(45, 15, 20) : Color.FromRgb(254, 242, 242));
                ToastActionStatus.Text = "Dosya AES-256 Karantina Kasasına kilitlendi.";
                ToastActionStatus.Foreground = new SolidColorBrush(Color.FromRgb(16, 185, 129));
            }
            else if (type.Equals("Success", StringComparison.OrdinalIgnoreCase))
            {
                AccentStripe.Background = new SolidColorBrush(Color.FromRgb(16, 185, 129)); // Green
                ToastTitle.Foreground = new SolidColorBrush(Color.FromRgb(16, 185, 129));
                BadgeIcon.Foreground = new SolidColorBrush(Color.FromRgb(16, 185, 129));
                BadgeIcon.Symbol = SymbolRegular.ShieldCheckmark24;
                IconBadge.Background = new SolidColorBrush(isDark ? Color.FromRgb(10, 35, 25) : Color.FromRgb(240, 253, 244));
                ToastActionStatus.Text = "Sistem tamamen temiz ve güvende.";
                ToastActionStatus.Foreground = new SolidColorBrush(Color.FromRgb(16, 185, 129));
            }
            else
            {
                AccentStripe.Background = new SolidColorBrush(Color.FromRgb(2, 132, 199)); // Blue
                ToastTitle.Foreground = new SolidColorBrush(isDark ? Color.FromRgb(56, 189, 248) : Color.FromRgb(2, 132, 199));
                BadgeIcon.Foreground = new SolidColorBrush(Color.FromRgb(2, 132, 199));
                BadgeIcon.Symbol = SymbolRegular.Info24;
                IconBadge.Background = new SolidColorBrush(isDark ? Color.FromRgb(15, 30, 50) : Color.FromRgb(240, 249, 255));
                ToastActionStatus.Text = "Ultron Defender gerçek zamanlı koruma aktif.";
                ToastActionStatus.Foreground = new SolidColorBrush(Color.FromRgb(2, 132, 199));
            }
        }

        private void CloseToast()
        {
            _closeTimer?.Stop();
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(200));
            fadeOut.Completed += (s, e) => Close();
            BeginAnimation(OpacityProperty, fadeOut);
        }

        private void OnCardClicked(object sender, MouseButtonEventArgs e)
        {
            try
            {
                var mainWindow = Application.Current?.MainWindow as MainWindow;
                if (mainWindow != null)
                {
                    mainWindow.ShowAndActivate();
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
            }
            catch { }
            CloseToast();
        }

        private void OnMinimizeClicked(object sender, RoutedEventArgs e)
        {
            CloseToast();
        }

        private void OnCloseClicked(object sender, RoutedEventArgs e)
        {
            CloseToast();
        }
    }
}