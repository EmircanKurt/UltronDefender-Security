using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.DependencyInjection;
using Wpf.Ui.Controls;

namespace AegisPC.App.Views
{
    /// <summary>
    /// Sağ alttan kayarak açılan, koyu temalı (#151515, #262626) ve ESET tarzı
    /// modern animasyonlu Windows bildirim penceresi.
    /// </summary>
    public partial class ToastNotificationWindow : Window
    {
        private System.Windows.Threading.DispatcherTimer? _closeTimer;
        private System.Windows.Threading.DispatcherTimer? _pulseTimer;
        private static ToastNotificationWindow? _activeToast;
        private static readonly object _toastLock = new();
        private string _currentType = "Info";

        public Type? CustomTargetPage { get; set; }
        public Action? CustomClickAction { get; set; }

        public ToastNotificationWindow()
        {
            InitializeComponent();
        }

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

        public void UpdateContent(string title, string message, string type)
        {
            _currentType = type;
            ToastTitle.Text = CleanTitle(title);
            ToastMessage.Text = message;
            ApplyStyling(type);

            // Nabız animasyonunu ve sayaçları sıfırla, pencere konumu sabit kalır
            _pulseTimer?.Stop();
            AccentStripe.BeginAnimation(UIElement.OpacityProperty, null);
            AccentStripe.Opacity = 1.0;

            _closeTimer?.Stop();
            if (_closeTimer != null) _closeTimer.Interval = TimeSpan.FromSeconds(8);
            if (_pulseTimer != null) _pulseTimer.Interval = TimeSpan.FromSeconds(6);
            _closeTimer?.Start();
            _pulseTimer?.Start();
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

            // 250ms slide-in + fade-in animasyonu (CubicEase EaseOut)
            Opacity = 0;
            CardTranslate.Y = 40;

            var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
            var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(250)) { EasingFunction = ease };
            var slideIn = new DoubleAnimation(40, 0, TimeSpan.FromMilliseconds(250)) { EasingFunction = ease };

            BeginAnimation(OpacityProperty, fadeIn);
            CardTranslate.BeginAnimation(TranslateTransform.YProperty, slideIn);

            // Kapanmadan önceki son 2 saniyede nabız animasyonu için zamanlayıcı (8s - 2s = 6s)
            _pulseTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(6)
            };
            _pulseTimer.Tick += (s, e) =>
            {
                _pulseTimer.Stop();
                StartStripePulseAnimation();
            };
            _pulseTimer.Start();

            // 8 saniye sonra otomatik kapanma zamanlayıcısı
            _closeTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(8)
            };
            _closeTimer.Tick += (s, e) => CloseToast();
            _closeTimer.Start();
        }

        private void StartStripePulseAnimation()
        {
            try
            {
                var pulseAnim = new DoubleAnimation
                {
                    From = 1.0,
                    To = 0.35,
                    Duration = TimeSpan.FromMilliseconds(500),
                    AutoReverse = true,
                    RepeatBehavior = new RepeatBehavior(2) // 2 döngü = 2000ms = 2 saniye
                };
                AccentStripe.BeginAnimation(UIElement.OpacityProperty, pulseAnim);
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Nabız animasyonu başlatılamadı.");
            }
        }

        public static string CleanTitle(string title)
        {
            if (string.IsNullOrWhiteSpace(title)) return "Tehdit engellendi";
            return title.Replace("🚨", "").Replace("🛡️", "").Replace("⚠️", "").Trim();
        }

        private void ApplyStyling(string type)
        {
            // Dinamik tema fırçaları (Açık ve Koyu mod ile uyumlu)
            CardBorder.SetResourceReference(Border.BackgroundProperty, "BrushCardBg");
            CardBorder.SetResourceReference(Border.BorderBrushProperty, "BrushCardBorder");
            ToastMessage.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "BrushTextSecondary");
            if (AppHeaderTitle != null) AppHeaderTitle.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "BrushTextPrimary");

            if (type.Equals("Warning", StringComparison.OrdinalIgnoreCase))
            {
                var orange = Color.FromRgb(245, 158, 11); // #F59E0B Turuncu
                var orangeBrush = new SolidColorBrush(orange);
                AccentStripe.Background = orangeBrush;
                HeaderBadge.Background = orangeBrush;
                ToastTitle.Foreground = orangeBrush;
                BadgeIcon.Foreground = orangeBrush;
                BadgeIcon.Symbol = SymbolRegular.Warning24;
                IconBadge.Background = new SolidColorBrush(Color.FromRgb(42, 30, 16));
                ToastActionStatus.Text = "Güvenlik incelemesi için Olay Merkezine kaydedildi.";
                ToastActionStatus.Foreground = orangeBrush;
            }
            else if (type.Equals("Error", StringComparison.OrdinalIgnoreCase) || 
                     type.Equals("Danger", StringComparison.OrdinalIgnoreCase))
            {
                var red = Color.FromRgb(239, 68, 68); // #EF4444 Kırmızı
                var redBrush = new SolidColorBrush(red);
                AccentStripe.Background = redBrush;
                HeaderBadge.Background = redBrush;
                ToastTitle.Foreground = redBrush;
                BadgeIcon.Foreground = redBrush;
                BadgeIcon.Symbol = SymbolRegular.Warning24;
                IconBadge.Background = new SolidColorBrush(Color.FromRgb(42, 18, 21));
                ToastActionStatus.Text = "Dosya AES-256 Karantina Kasasına kilitlendi.";
                ToastActionStatus.Foreground = new SolidColorBrush(Color.FromRgb(16, 185, 129)); // Yeşil onay
            }
            else if (type.Equals("Success", StringComparison.OrdinalIgnoreCase))
            {
                var green = Color.FromRgb(16, 185, 129); // #10B981 Yeşil
                var greenBrush = new SolidColorBrush(green);
                AccentStripe.Background = greenBrush;
                HeaderBadge.Background = greenBrush;
                ToastTitle.Foreground = greenBrush;
                BadgeIcon.Foreground = greenBrush;
                BadgeIcon.Symbol = SymbolRegular.ShieldCheckmark24;
                IconBadge.Background = new SolidColorBrush(Color.FromRgb(16, 42, 30));
                ToastActionStatus.Text = "Sistem tamamen temiz ve güvende.";
                ToastActionStatus.Foreground = greenBrush;
            }
            else
            {
                var blue = Color.FromRgb(2, 132, 199); // #0284C7 Mavi
                var blueBrush = new SolidColorBrush(blue);
                AccentStripe.Background = blueBrush;
                HeaderBadge.Background = blueBrush;
                ToastTitle.Foreground = new SolidColorBrush(Color.FromRgb(56, 189, 248));
                BadgeIcon.Foreground = new SolidColorBrush(Color.FromRgb(56, 189, 248));
                BadgeIcon.Symbol = SymbolRegular.Info24;
                IconBadge.Background = new SolidColorBrush(Color.FromRgb(16, 32, 48));
                ToastActionStatus.Text = "Ultron Defender gerçek zamanlı koruma aktif.";
                ToastActionStatus.Foreground = new SolidColorBrush(Color.FromRgb(56, 189, 248));
            }
        }

        private void CloseToast()
        {
            _pulseTimer?.Stop();
            _closeTimer?.Stop();
            AccentStripe.BeginAnimation(UIElement.OpacityProperty, null);
            AccentStripe.Opacity = 1.0;

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
            _pulseTimer?.Stop();
            _closeTimer?.Stop();
            AccentStripe.BeginAnimation(UIElement.OpacityProperty, null);
            AccentStripe.Opacity = 1.0;
        }

        private void OnCardMouseLeave(object sender, MouseEventArgs e)
        {
            // Kullanıcı fareyi bildirimden çektiğinde 3 saniye süre ver
            // Son 2 saniyede nabız animasyonu başlaması için pulseTimer 1 saniye sonra devreye girer
            if (_pulseTimer != null)
            {
                _pulseTimer.Interval = TimeSpan.FromSeconds(1);
                _pulseTimer.Start();
            }

            if (_closeTimer != null)
            {
                _closeTimer.Interval = TimeSpan.FromSeconds(3);
                _closeTimer.Start();
            }
        }

        private void OnFooterActionClicked(object sender, MouseButtonEventArgs e)
        {
            e.Handled = true;
            NavigateAndClose();
        }

        private void OnCardClicked(object sender, MouseButtonEventArgs e)
        {
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

        private void OnMinimizeClicked(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            CloseToast();
        }

        private void OnCloseClicked(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            CloseToast();
        }
    }
}