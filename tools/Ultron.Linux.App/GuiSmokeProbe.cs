using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Interactivity;
using Avalonia.Media.Imaging;

namespace Ultron.Linux.App;

// Invoked only by the explicit --gui-smoke <output-directory> CI command.
// This uses the real platform backend, shows an X11 window and manually scans one inert fixture.
internal static class GuiSmokeProbe
{
    internal static void Attach(Window window, IClassicDesktopStyleApplicationLifetime lifetime, string outputDirectory)
    {
        window.Opened += async (_, _) =>
        {
            string? fixtureDirectory = null;
            try
            {
                if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("GUI runtime evidence requires an actual Linux process.");
                string output = Path.GetFullPath(outputDirectory);
                Directory.CreateDirectory(output);
                await Task.Delay(400);
                var handle = window.TryGetPlatformHandle();
                if (!window.IsVisible || handle?.Handle == IntPtr.Zero || handle == null)
                    throw new InvalidOperationException("No visible native platform window was created.");
                var state = (ScanPresentation)(window.DataContext ?? throw new InvalidOperationException("Missing UI state."));
                if (state.IsScanning || state.CanStart) throw new InvalidOperationException("Unexpected startup scan or selected scope.");
                SaveFrame(window, Path.Combine(output, "linux-x11-startup.png"));
                fixtureDirectory = Directory.CreateTempSubdirectory("ultron-linux-gui-inert-").FullName;
                string fixture = Path.Combine(fixtureDirectory, "ordinary.txt");
                await File.WriteAllTextAsync(fixture, "Inert Linux GUI fixture. No executable content.\n");
                state.SelectedPath = fixture;
                window.FindControl<Button>("StartButton")!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                while (state.IsScanning) await Task.Delay(30, timeout.Token);
                if (state.Rows.Count != 1 || !state.CanExport || !state.Rows[0].Detail.Contains("Text", StringComparison.Ordinal))
                    throw new InvalidOperationException("The GUI manual scan did not produce its inert text report.");
                SaveFrame(window, Path.Combine(output, "linux-x11-scan.png"));
                await File.WriteAllTextAsync(Path.Combine(output, "gui-runtime.json"), JsonSerializer.Serialize(new
                {
                    ActualLinuxRuntime = true, VisibleNativeWindow = window.IsVisible, NativeHandle = handle.Handle.ToInt64(),
                    PlatformHandleDescriptor = handle.HandleDescriptor, NoStartupScan = true, ManualInertScanReports = state.Rows.Count,
                    Width = window.Bounds.Width, Height = window.Bounds.Height, MalwareFreeClaim = false,
                    NativePickersVerified = false, ProtectionVerified = false, Outcome = "GuiRuntimeSmokePassed"
                }, new JsonSerializerOptions { WriteIndented = true }));
                lifetime.Shutdown(0);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Linux GUI smoke failed: " + ex);
                lifetime.Shutdown(1);
            }
            finally
            {
                if (fixtureDirectory != null) Directory.Delete(fixtureDirectory, recursive: true);
            }
        };
    }

    private static void SaveFrame(Window window, string path)
    {
        using var image = new RenderTargetBitmap(new PixelSize((int)window.Bounds.Width, (int)window.Bounds.Height));
        image.Render(window);
        image.Save(path, PngBitmapEncoderOptions.Default);
    }
}
