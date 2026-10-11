using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using Ultron.Linux.App;
using Ultron.PortableInspection;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Ultron.Linux.Tests;

/// <summary>Builds the real preview theme and XAML controls with the official headless Skia test backend.</summary>
public sealed class HeadlessAppBuilder
{
    /// <summary>Configures real text and pixel rendering without requiring a desktop display.</summary>
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<LinuxApplication>().UseSkia()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });
}

/// <summary>Verifies real GUI bindings and startup behavior; this does not prove native pickers or Linux protection.</summary>
public sealed class GraphicalShellTests
{
    /// <summary>Verifies startup has no selected scope or scan and captures the genuine rendered application view.</summary>
    [Fact]
    public async Task StartupHasNoScanAndRendersRealControls()
    {
        using var session = HeadlessUnitTestSession.StartNew(typeof(HeadlessAppBuilder));
        await session.Dispatch(() =>
        {
            var window = new MainWindow();
            try
            {
                window.Show(); Dispatcher.UIThread.RunJobs();
                var state = Assert.IsType<ScanPresentation>(window.DataContext);
                Assert.Empty(state.SelectedPath); Assert.False(state.IsScanning); Assert.Empty(state.Rows);
                Assert.False(window.FindControl<Button>("StartButton")!.IsEnabled);
                Assert.False(window.FindControl<Button>("CancelButton")!.IsEnabled);
                Assert.False(window.FindControl<Button>("ExportButton")!.IsEnabled);
                using var frame = window.CaptureRenderedFrame();
                Assert.NotNull(frame);
                Assert.True(frame.PixelSize.Width >= 850);
                Assert.True(frame.PixelSize.Height >= 650);
                string? captureDirectory = Environment.GetEnvironmentVariable("ULTRON_TEST_SCREENSHOT_DIR");
                if (!string.IsNullOrWhiteSpace(captureDirectory))
                {
                    Directory.CreateDirectory(captureDirectory);
                    frame.Save(Path.Combine(captureDirectory, "linux-preview-startup.png"), PngBitmapEncoderOptions.Default);
                }
            }
            finally { window.Close(); }
        }, CancellationToken.None);
    }

    /// <summary>Verifies selecting scope changes the start button without starting work and result rows bind correctly.</summary>
    [Fact]
    public async Task ScopeAndResultsBindWithoutAutomaticScan()
    {
        using var session = HeadlessUnitTestSession.StartNew(typeof(HeadlessAppBuilder));
        await session.Dispatch(() =>
        {
            var window = new MainWindow();
            try
            {
                window.Show();
                var state = Assert.IsType<ScanPresentation>(window.DataContext);
                state.SelectedPath = "/tmp/ultron-inert-fixture"; Dispatcher.UIThread.RunJobs();
                Assert.False(state.IsScanning);
                Assert.True(window.FindControl<Button>("StartButton")!.IsEnabled);
                Assert.Equal(state.SelectedPath, window.FindControl<TextBox>("ScopeBox")!.Text);
                state.IsScanning = true; Dispatcher.UIThread.RunJobs();
                Assert.False(window.FindControl<Button>("StartButton")!.IsEnabled);
                Assert.True(window.FindControl<Button>("PauseButton")!.IsEnabled);
                Assert.True(window.FindControl<ProgressBar>("ScanProgress")!.IsIndeterminate);
                state.Add(new InspectionReport { Path = state.SelectedPath, Limitations = ["Fixture unsupported coverage"] });
                state.IsScanning = false; Dispatcher.UIThread.RunJobs();
                Assert.True(window.FindControl<Button>("ExportButton")!.IsEnabled);
                Assert.Single(window.FindControl<ListBox>("ResultsList")!.Items);
                Assert.Equal("Bilinmiyor / eksik inceleme", Assert.Single(state.Rows).DisplayStatus);
            }
            finally { window.Close(); }
        }, CancellationToken.None);
    }
}
