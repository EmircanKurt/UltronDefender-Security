using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media.Animation;
using AegisPC.App.Helpers;

namespace AegisPC.App.Views
{
    /// <summary>
    /// Displays the product shield and theme-aware wordmark during startup without input tracking or repeating animations.
    /// </summary>
    public partial class SplashWindow : Window
    {
        /// <summary>Creates the startup presentation without changing the main application lifecycle.</summary>
        public SplashWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Closes the splash after an optional fade. Reduced motion, low rendering capability,
        /// hidden windows, and non-positive durations close immediately.
        /// </summary>
        public async Task FadeOutAndCloseAsync(int durationMs = 250)
        {
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            EventHandler onClosed = (_, _) => tcs.TrySetResult(true);
            try
            {
                if (durationMs <= 0 || !UiMotionPolicy.CanAnimate || !IsVisible || WindowState == WindowState.Minimized)
                {
                    Close();
                    return;
                }
                Closed += onClosed;
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
                        Serilog.Log.Warning(ex, "Splash window could not be closed after its fade.");
                    }
                    tcs.TrySetResult(true);
                };

                BeginAnimation(OpacityProperty, anim);
                await tcs.Task;
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Splash window fade failed.");
                try { Close(); }
                catch (Exception closeException) { Serilog.Log.Warning(closeException, "Splash window fallback close failed."); }
                tcs.TrySetResult(false);
            }
            finally
            {
                Closed -= onClosed;
            }
        }
    }
}
