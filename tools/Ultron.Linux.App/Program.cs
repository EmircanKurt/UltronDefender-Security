using Avalonia;

namespace Ultron.Linux.App;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args) => BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

    internal static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<LinuxApplication>().UsePlatformDetect();
}
