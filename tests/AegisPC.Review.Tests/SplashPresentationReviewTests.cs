using System.IO;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using AegisPC.App.Controls;
using AegisPC.App.Views;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Offscreen splash fixtures; never start Ultron, show a native window or enable protection.</summary>
public sealed class SplashPresentationReviewTests
{
    /// <summary>Checks the actual splash tree and product logo in both themes and common DPI scales.</summary>
    [Theory]
    [InlineData("Light", 96)] [InlineData("Dark", 96)]
    [InlineData("Light", 192)] [InlineData("Dark", 144)]
    public void SplashUsesStaticProductLogoAndReadableTheme(string theme, int dpi) => RunSta(() =>
    {
        var splash = new SplashWindow();
        try
        {
            Assert.False(splash.IsVisible);
            var logo = Assert.IsType<Image>(splash.FindName("StartupLogo"));
            var image = Assert.IsAssignableFrom<BitmapSource>(logo.Source);
            var expected = BitmapFrame.Create(new Uri("pack://application:,,,/UltronDefender;component/Resources/Images/ultron_logo.png"),
                BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
            Assert.Equal(expected.Format, image.Format);
            Assert.Equal(expected.PixelWidth, image.PixelWidth); Assert.Equal(expected.PixelHeight, image.PixelHeight);
            int stride = (image.PixelWidth * image.Format.BitsPerPixel + 7) / 8;
            var actualPixels = new byte[stride * image.PixelHeight]; var expectedPixels = new byte[actualPixels.Length];
            image.CopyPixels(actualPixels, stride, 0); expected.CopyPixels(expectedPixels, stride, 0);
            Assert.True(actualPixels.AsSpan().SequenceEqual(expectedPixels), "Splash must reuse the exact product logo pixels.");
            Assert.True(image.PixelWidth > 0); Assert.True(image.PixelHeight > 0);
            Assert.False(logo.Focusable); Assert.False(logo.IsHitTestVisible);
            var surface = Assert.IsType<Border>(splash.Content);
            splash.Content = null;
            surface.Resources.MergedDictionaries.Add(new ResourceDictionary
                { Source = new Uri($"/UltronDefender;component/Resources/Themes/Colors.{theme}.xaml", UriKind.Relative) });
            surface.Width = 440; surface.Height = 270;
            surface.Measure(new Size(440, 270)); surface.Arrange(new Rect(0, 0, 440, 270)); surface.UpdateLayout();
            Assert.Empty(Descendants<UltronRobot>(surface));
            Assert.Equal(new CornerRadius(8), surface.CornerRadius);
            var texts = Descendants<TextBlock>(surface).ToArray();
            Assert.Contains(texts, text => text.Text == "ULTRON");
            Assert.Contains(texts, text => text.Text == "Defender");
            Assert.DoesNotContain(texts, text => text.Text.Contains("Gelişmiş Uç Nokta", StringComparison.Ordinal));
            foreach (var text in texts)
            {
                Assert.False(text.HasAnimatedProperties);
                var bounds = text.TransformToAncestor(surface).TransformBounds(new Rect(0, 0, text.ActualWidth, text.ActualHeight));
                Assert.True(bounds.Left >= 0 && bounds.Right <= 440 && bounds.Top >= 0 && bounds.Bottom <= 270);
                Assert.True(Contrast(Assert.IsType<SolidColorBrush>(text.Foreground).Color,
                    Assert.IsType<SolidColorBrush>(surface.Background).Color) >= 4.5, text.Text);
            }
            var bitmap = new RenderTargetBitmap(440 * dpi / 96, 270 * dpi / 96, dpi, dpi, PixelFormats.Pbgra32);
            bitmap.Render(surface);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
            string folder = Path.Combine(AppContext.BaseDirectory, "SplashPreview"); Directory.CreateDirectory(folder);
            using var file = File.Create(Path.Combine(folder, $"splash-{theme}-{dpi}.png"));
            encoder.Save(file); Assert.True(file.Length > 500);
        }
        finally { splash.Close(); }
    });

    /// <summary>An unshown splash still closes immediately without starting an animation.</summary>
    [Fact]
    public void HiddenSplashClosesWithoutAnimation() => RunSta(() =>
    {
        var splash = new SplashWindow(); bool closed = false;
        splash.Closed += (_, _) => closed = true;
        var completion = splash.FadeOutAndCloseAsync(0);
        Assert.True(completion.IsCompletedSuccessfully);
        Assert.True(closed); Assert.False(splash.HasAnimatedProperties);
    });

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T typed) yield return typed;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }

    private static double Contrast(Color a, Color b)
    {
        static double L(Color c)
        {
            static double Linear(byte x) { double v = x / 255d; return v <= .04045 ? v / 12.92 : Math.Pow((v + .055) / 1.055, 2.4); }
            return .2126 * Linear(c.R) + .7152 * Linear(c.G) + .0722 * Linear(c.B);
        }
        return (Math.Max(L(a), L(b)) + .05) / (Math.Min(L(a), L(b)) + .05);
    }

    private static void RunSta(Action action)
    {
        Exception? error = null;
        var thread = new Thread(() => { try { action(); } catch (Exception exception) { error = exception; }
            finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); } }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA); thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(15)), "Inert splash check exceeded its budget.");
        if (error != null) ExceptionDispatchInfo.Capture(error).Throw();
    }
}
