using Avalonia;

namespace Ultron.Linux.App;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            using var lease = OperatingSystem.IsLinux() ? ApplicationLifetimeLease.Acquire() : null;
            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("Linux preview startup failed: " + error);
            return 1;
        }
    }

    internal static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<LinuxApplication>().UsePlatformDetect();
}
