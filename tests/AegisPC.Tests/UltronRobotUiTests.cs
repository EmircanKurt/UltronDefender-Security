using System;
using System.Reflection;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using ShapePath = System.Windows.Shapes.Path;
using System.Windows.Threading;
using AegisPC.App.Controls;
using AegisPC.App.Helpers;
using Xunit;
using Point = System.Windows.Point;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;

namespace AegisPC.Tests;

/// <summary>
/// Exercises robot policy and isolated STA controls without starting the application,
/// showing native windows, changing persisted theme settings, or activating protection services.
/// </summary>
public sealed class UltronRobotUiTests
{
    /// <summary>Checks that every lifecycle gate independently prevents pointer tracking.</summary>
    [Theory]
    [InlineData(false, true, true, true, false, true)]
    [InlineData(true, false, true, true, false, true)]
    [InlineData(true, true, false, true, false, true)]
    [InlineData(true, true, true, false, false, true)]
    [InlineData(true, true, true, true, true, true)]
    [InlineData(true, true, true, true, false, false)]
    public void IneligibleLifecycle_DoesNotTrackPointer(bool loaded, bool visible, bool windowVisible,
        bool active, bool minimized, bool motionAllowed) =>
        Assert.False(RobotMotionPolicy.CanTrackPointer(loaded, visible, windowVisible, active, minimized, motionAllowed));

    /// <summary>Checks that an eligible local window can enable tracking.</summary>
    [Fact]
    public void EligibleLifecycle_CanTrackPointer() =>
        Assert.True(RobotMotionPolicy.CanTrackPointer(true, true, true, true, false, true));

    /// <summary>Verifies reduced motion and low or unknown rendering tiers use a static presentation.</summary>
    [Theory]
    [InlineData(false, 2, false)]
    [InlineData(false, 3, false)]
    [InlineData(true, -1, false)]
    [InlineData(true, 0, false)]
    [InlineData(true, 1, false)]
    [InlineData(true, 2, true)]
    public void WindowsAndRenderPolicy_GatesMotion(bool enabled, int tier, bool expected) =>
        Assert.Equal(expected, UiMotionPolicy.ShouldAnimate(enabled, tier));

    /// <summary>Checks that pointer extremes cannot move the terminal face beyond its DIP budget.</summary>
    [Theory]
    [InlineData(-1000000, -1000000)]
    [InlineData(1000000, 1000000)]
    [InlineData(-1000000, 1000000)]
    [InlineData(50, 46)]
    public void LocalGaze_RemainsBounded(double x, double y)
    {
        Point gaze = RobotMotionPolicy.CalculateGaze(new Point(x, y), new Point(50, 46));
        Assert.InRange(gaze.X, -2.5, 2.5);
        Assert.InRange(gaze.Y, -2.5, 2.5);
        if (x == 50 && y == 46) Assert.Equal(new Point(), gaze);
    }

    /// <summary>Rejects invalid numeric coordinates before they reach a WPF transform.</summary>
    [Fact]
    public void InvalidGaze_ReturnsNeutralPose()
    {
        Assert.Equal(new Point(), RobotMotionPolicy.CalculateGaze(new Point(double.NaN, 1), new Point()));
        Assert.Equal(new Point(), RobotMotionPolicy.CalculateGaze(new Point(1, double.PositiveInfinity), new Point()));
        Assert.Equal(new Point(), RobotMotionPolicy.CalculateGaze(new Point(1, 2), new Point(double.NaN, 0)));
    }

    /// <summary>Checks finite convergence, no overshoot, and the maximum visual update frequency.</summary>
    [Fact]
    public void Motion_SettlesExactlyWithinTheUpdateBudget()
    {
        double current = -2.5;
        for (int step = 0; step < 60; step++)
        {
            double previous = current;
            current = RobotMotionPolicy.Approach(current, 2.5);
            Assert.InRange(current, previous, 2.5);
        }
        Assert.Equal(2.5, current);
        Assert.Equal(2.5, RobotMotionPolicy.Approach(current, 2.5));
        Assert.True(RobotMotionPolicy.UpdateInterval.TotalSeconds >= 1d / 30);
    }

    /// <summary>Checks command binding, the standard Button automation action, and keyboard focus affordances.</summary>
    [Fact]
    public void RobotAction_IsAccessibleAndInvokesOnlyItsCommand() => RunSta(() =>
    {
        var command = new RecordingCommand();
        var robot = new UltronRobot { Command = command };
        var button = Assert.IsType<Button>(robot.FindName("RobotButton"));
        Assert.Same(command, button.Command);
        Assert.True(button.Focusable);
        Assert.True(button.IsTabStop);
        Assert.Equal("Ultron AI Koruma Merkezi’ni aç", AutomationProperties.GetName(button));
        Assert.NotEmpty(AutomationProperties.GetHelpText(button));
        button.ApplyTemplate();
        Assert.Contains(button.Template.Triggers.Cast<TriggerBase>(), trigger =>
            trigger is Trigger t && t.Property == UIElement.IsKeyboardFocusedProperty);
        var peer = new ButtonAutomationPeer(button);
        var invoke = Assert.IsAssignableFrom<IInvokeProvider>(peer.GetPattern(PatternInterface.Invoke));
        invoke.Invoke();
        PumpDispatcher();
        Assert.Equal(1, command.ExecutionCount);
    });

    /// <summary>Checks the dynamic vector accent without creating Application or writing the user's theme preference.</summary>
    [Fact]
    public void ThemeResources_UpdateTheVectorAccentInPlace() => RunSta(() =>
    {
        var robot = new UltronRobot();
        var shell = Assert.IsType<ShapePath>(robot.FindName("RobotShell"));
        robot.Resources.MergedDictionaries.Add(LoadTheme("Dark"));
        Assert.Equal(Color.FromRgb(0x3B, 0x82, 0xF6), Assert.IsType<SolidColorBrush>(shell.Stroke).Color);
        robot.Resources.MergedDictionaries.Clear();
        robot.Resources.MergedDictionaries.Add(LoadTheme("Light"));
        Assert.Equal(Color.FromRgb(0xEF, 0x44, 0x44), Assert.IsType<SolidColorBrush>(shell.Stroke).Color);
        Assert.Equal(100, robot.Width);
        Assert.Equal(92, robot.Height);
    });

    /// <summary>Checks repeated synthetic load/unload detach and timer cancellation without displaying an OS window.</summary>
    [Fact]
    public void Unload_StopsMotionAndDetachesOwnerSubscriptions() => RunSta(() =>
    {
        var robot = new UltronRobot();
        var owner = new Window { Content = robot };
        var timer = GetPrivateField<DispatcherTimer>(robot, "_motionTimer");
        try
        {
            for (int iteration = 0; iteration < 3; iteration++)
            {
                robot.RaiseEvent(new RoutedEventArgs(FrameworkElement.LoadedEvent));
                robot.RaiseEvent(new RoutedEventArgs(FrameworkElement.LoadedEvent));
                Assert.True(GetPrivateField<bool>(robot, "_isAttached"));
                Assert.False(GetPrivateField<bool>(robot, "_isTrackingPointer"));
                Assert.False(timer.IsEnabled);
                var gaze = Assert.IsType<TranslateTransform>(robot.FindName("GazeTransform"));
                gaze.X = 2;
                timer.Start();
                robot.RaiseEvent(new RoutedEventArgs(FrameworkElement.UnloadedEvent));
                Assert.False(timer.IsEnabled);
                Assert.False(GetPrivateField<bool>(robot, "_isAttached"));
                Assert.Null(GetPrivateField<Window?>(robot, "_owner"));
                Assert.Equal(0, gaze.X);
            }
        }
        finally
        {
            robot.RaiseEvent(new RoutedEventArgs(FrameworkElement.UnloadedEvent));
            owner.Content = null;
            owner.Close();
        }
    });

    /// <summary>Checks that startup decoration has no keyboard, automation command, or motion interaction.</summary>
    [Fact]
    public void DecorativeRobot_IsStaticAndCannotInvokeTheCommand() => RunSta(() =>
    {
        var command = new RecordingCommand();
        var robot = new UltronRobot { Command = command, IsInteractive = false, IsMotionEnabled = false };
        var button = Assert.IsType<Button>(robot.FindName("RobotButton"));
        Assert.False(button.Focusable);
        Assert.False(button.IsTabStop);
        Assert.False(button.IsHitTestVisible);
        Assert.False(button.IsEnabled);
        Assert.False(GetPrivateField<DispatcherTimer>(robot, "_motionTimer").IsEnabled);
        Assert.False(GetPrivateField<bool>(robot, "_isAttached"));
        var peer = new ButtonAutomationPeer(button);
        var invoke = Assert.IsAssignableFrom<IInvokeProvider>(peer.GetPattern(PatternInterface.Invoke));
        Assert.Throws<ElementNotEnabledException>(() => invoke.Invoke());
        Assert.Equal(0, command.ExecutionCount);
    });

    /// <summary>Renders both themes at common DPIs without launching the installed application or showing a window.</summary>
    [Theory]
    [InlineData("Dark", 96)]
    [InlineData("Light", 96)]
    [InlineData("Dark", 144)]
    [InlineData("Light", 192)]
    public void RobotThemeDpi_OffscreenPreview(string theme, int dpi) => RunSta(() =>
    {
        var robot = new UltronRobot { IsMotionEnabled = false };
        robot.Resources.MergedDictionaries.Add(LoadTheme(theme));
        var background = new Border { Width = 180, Height = 140, Child = robot,
            Background = new SolidColorBrush(theme == "Light" ? Colors.White : Color.FromRgb(13, 13, 13)) };
        background.Measure(new System.Windows.Size(180, 140));
        background.Arrange(new Rect(0, 0, 180, 140));
        background.UpdateLayout();
        var bitmap = new System.Windows.Media.Imaging.RenderTargetBitmap(180 * dpi / 96, 140 * dpi / 96,
            dpi, dpi, PixelFormats.Pbgra32);
        bitmap.Render(background);
        var encoder = new System.Windows.Media.Imaging.PngBitmapEncoder();
        encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
        string folder = System.IO.Path.Combine(AppContext.BaseDirectory, "UiPreview");
        System.IO.Directory.CreateDirectory(folder);
        using var file = System.IO.File.Create(System.IO.Path.Combine(folder, $"robot-{theme}-{dpi}.png"));
        encoder.Save(file);
        Assert.True(file.Length > 100);
    });

    private static ResourceDictionary LoadTheme(string theme) => new()
    {
        Source = new Uri($"/UltronDefender;component/Resources/Themes/Colors.{theme}.xaml", UriKind.Relative)
    };

    private static T GetPrivateField<T>(UltronRobot robot, string name)
    {
        FieldInfo? field = typeof(UltronRobot).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);
        return (T)field.GetValue(robot)!;
    }

    private static void PumpDispatcher()
    {
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
    }

    private static void RunSta(Action action)
    {
        Exception? error = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception exception) { error = exception; }
            finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); }
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "The isolated STA UI check did not finish within its budget.");
        if (error != null) ExceptionDispatchInfo.Capture(error).Throw();
    }

    private sealed class RecordingCommand : ICommand
    {
        /// <summary>Gets the number of observed command invocations in this isolated fixture.</summary>
        public int ExecutionCount { get; private set; }
        /// <summary>Provides the required notification contract for the always-available fixture command.</summary>
        public event EventHandler? CanExecuteChanged { add { } remove { } }
        /// <summary>Allows the fixture command without calling application services.</summary>
        public bool CanExecute(object? parameter) => true;
        /// <summary>Records the invocation without performing navigation or changing external state.</summary>
        public void Execute(object? parameter) => ExecutionCount++;
    }
}
