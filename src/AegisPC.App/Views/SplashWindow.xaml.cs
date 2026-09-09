using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media.Animation;

namespace AegisPC.App.Views
{
    /// <summary>
    /// Program açılışında gösterilen 1.5 - 2 saniyelik modern animasyonlu splash penceresi.
    /// Koyu arka plan (#0D0D0D), Codex bulut logosu, yanıp sönen imleç çizgisi ve belirsiz yükleme barı içerir.
    /// </summary>
    public partial class SplashWindow : Window
    {
        public SplashWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Belirtilen süre boyunca pencere opaklığını 0'a indirir (fade-out) ve ardından pencereyi kapatır.
        /// </summary>
        public async Task FadeOutAndCloseAsync(int durationMs = 250)
        {
            var tcs = new TaskCompletionSource<bool>();
            try
            {
                var anim = new DoubleAnimation
                {
                    From = Opacity,
                    To = 0.0,
                    Duration = TimeSpan.FromMilliseconds(durationMs),
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
                };

                anim.Completed += (s, e) =>
                {
                    try
                    {
                        Close();
                    }
                    catch (Exception ex)
                    {
                        Serilog.Log.Warning(ex, "SplashWindow kapatılırken hata oluştu.");
                    }
                    tcs.TrySetResult(true);
                };

                BeginAnimation(OpacityProperty, anim);
                await tcs.Task;
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "SplashWindow fade-out animasyonunda hata oluştu.");
                try { Close(); } catch { }
                tcs.TrySetResult(false);
            }
        }
    }
}
