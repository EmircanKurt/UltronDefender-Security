using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;

namespace Ultron.Linux.App;

/// <summary>Creates the independent Linux preview shell without starting scans or platform protection services.</summary>
public sealed class LinuxApplication : Application
{
    /// <summary>Loads the MIT Avalonia Fluent theme and the dark preview appearance.</summary>
    public override void Initialize()
    {
        RequestedThemeVariant = ThemeVariant.Dark;
        Styles.Add(new FluentTheme());
    }

    /// <summary>Opens the manual scan view; Windows service and protection capabilities are never initialized here.</summary>
    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow();
            if (desktop.Args is ["--gui-smoke", var directory])
                GuiSmokeProbe.Attach(desktop.MainWindow, desktop, directory);
        }
        base.OnFrameworkInitializationCompleted();
    }
}
