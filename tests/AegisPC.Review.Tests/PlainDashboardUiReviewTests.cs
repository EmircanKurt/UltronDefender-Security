using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using AegisPC.App.Controls;
using AegisPC.App.Helpers;
using AegisPC.App.Services;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Renders native dashboard controls without launching Ultron, services or scans.</summary>
public sealed class PlainDashboardUiReviewTests
{
    /// <summary>Verifies text bounds, button contrast and responsive columns in both themes and multiple DPIs.</summary>
    [Theory]
    [InlineData("Light", 1000, 96)] [InlineData("Dark", 1000, 96)]
    [InlineData("Light", 720, 144)] [InlineData("Dark", 720, 144)]
    [InlineData("Light", 360, 192)] [InlineData("Dark", 420, 192)]
    public void NativeLayoutIsReadableAndResponsive(string theme, int width, int dpi) => RunSta(() =>
    {
        var surface = new PlainDashboardSurface { DataContext = Fixture(new RecordingCommand()) };
        var host = Host(surface, theme, width);
        Layout(host, width);
        var events = (Border)surface.FindName("EventsPanel");
        Assert.Equal(width - 48 < 680 ? 1 : 0, Grid.GetRow(events));
        Assert.True(surface.ActualWidth <= width - 48 + .1);
        foreach (var text in Descendants<TextBlock>(surface).Where(t => t.Visibility == Visibility.Visible && t.ActualWidth > 0 && t.ActualHeight > 0))
        {
            var bounds = text.TransformToAncestor(host).TransformBounds(new Rect(0, 0, text.ActualWidth, text.ActualHeight));
            Assert.True(bounds.Left >= -.5 && bounds.Right <= width + .5, $"Text escaped width: {text.Text}");
            Assert.False(text.HasAnimatedProperties);
        }
        foreach (string name in new[] { "BrushTextPrimary", "BrushTextSecondary", "BrushTextMuted" })
        {
            var foreground = ((SolidColorBrush)host.FindResource(name)).Color;
            foreach (string background in new[] { "BrushCardBg", "BrushAppBg" })
                Assert.True(Contrast(foreground, ((SolidColorBrush)host.FindResource(background)).Color) >= 4.5, name);
        }
        var quick = (Button)surface.FindName("QuickButton");
        Assert.IsType<SolidColorBrush>(quick.Background);
        Assert.True(Contrast(((SolidColorBrush)quick.Foreground).Color, ((SolidColorBrush)quick.Background).Color) >= 4.5);
        SaveRender(host, theme, width, dpi);
    });

    /// <summary>Native buttons invoke only externally supplied commands; construction starts nothing.</summary>
    [Fact]
    public void CommandsAndKeyboardFocusRemainAvailable() => RunSta(() =>
    {
        var command = new RecordingCommand();
        var surface = new PlainDashboardSurface { DataContext = Fixture(command) };
        var host = Host(surface, "Light", 900); Layout(host, 900);
        Assert.Equal(0, command.Count);
        foreach (string name in new[] { "QuickButton", "FullButton", "RefreshButton" })
        {
            var button = (Button)surface.FindName(name);
            Assert.True(button.Focusable); Assert.True(button.IsTabStop);
            Assert.NotNull(button.Command);
            ((IInvokeProvider)new ButtonAutomationPeer(button)).Invoke(); Pump();
        }
        Assert.Equal(3, command.Count);
    });

    /// <summary>Long content actually scrolls vertically, including wheel input, without horizontal escape.</summary>
    [Fact]
    public void SmallViewportPreservesWheelScrolling() => RunSta(() =>
    {
        var surface = new PlainDashboardSurface { DataContext = Fixture(new RecordingCommand()) };
        var scroll = new ScrollViewer { Content = surface, Width = 420, Height = 350,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            CanContentScroll = false };
        WheelScrollHelper.SetEnableRootRedirect(scroll, true);
        var host = Host(scroll, "Light", 420); Layout(host, 420);
        Assert.True(scroll.ScrollableHeight > 100);
        var button = (Button)surface.FindName("QuickButton");
        button.RaiseEvent(new MouseWheelEventArgs(Mouse.PrimaryDevice, 0, -120) { RoutedEvent = Mouse.PreviewMouseWheelEvent });
        Pump(); scroll.UpdateLayout();
        Assert.True(scroll.VerticalOffset > 0);
        scroll.ScrollToEnd(); scroll.UpdateLayout();
        Assert.True(scroll.VerticalOffset > 100); Assert.Equal(0, scroll.HorizontalOffset);
    });

    /// <summary>Running progress binds one-way and keeps the active scan route visible.</summary>
    [Fact]
    public void RunningScanPreservesProgressWithoutWritingBack() => RunSta(() =>
    {
        var surface = new PlainDashboardSurface { DataContext = Fixture(new RecordingCommand(), true) };
        var host = Host(surface, "Light", 900); Layout(host, 900);
        var progress = (ProgressBar)surface.FindName("ScanProgress");
        Assert.Equal(Visibility.Visible, ((StackPanel)progress.Parent).Visibility);
        Assert.True(progress.ActualHeight > 0); Assert.Equal(42, progress.Value);
        Assert.Equal(System.Windows.Data.BindingMode.OneWay,
            progress.GetBindingExpression(ProgressBar.ValueProperty)!.ParentBinding.Mode);
    });

    /// <summary>Active findings and actual event messages remain visible rather than being replaced by decorative summaries.</summary>
    [Fact]
    public void FindingsAndEventDetailsRemainAvailable() => RunSta(() =>
    {
        var surface = new PlainDashboardSurface { DataContext = Fixture(new RecordingCommand(), events: true) };
        var host = Host(surface, "Light", 900); Layout(host, 900);
        Assert.Equal(Visibility.Visible, ((Border)surface.FindName("FindingsPanel")).Visibility);
        Assert.Contains(Descendants<TextBlock>(surface), text => text.Text.Contains("İşlem başarısız; inceleme gerekiyor", StringComparison.Ordinal));
        Assert.DoesNotContain(Descendants<TextBlock>(surface), text => text.Text == "Henüz bu oturumda güvenlik olayı yok." && text.Visibility == Visibility.Visible);
    });

    private static object Fixture(RecordingCommand command, bool scanning = false, bool events = false) => new
    {
        DashboardPresentation = DashboardProtectionPresentation.Create(null, false, DateTime.UtcNow),
        StartQuickScanCommand = command, StartFullScanCommand = command, RefreshProtectionStatusCommand = command,
        OpenUltronProtectionCentreCommand = command, OpenActiveScanWindowCommand = command, ReviewThreatsCommand = command,
        IsScanning = scanning, HasThreatsDetected = events, ScanProgress = 42d, LastScanTime = "Henüz yapılmadı",
        LiveActivities = events ? new ObservableCollection<object> { new RealTimeActivityEvent
        { FileName = "Inert fixture.txt", Stage = "ACTION_FAILED", Message = "İşlem başarısız; inceleme gerekiyor" } } : new ObservableCollection<object>()
    };

    private static Border Host(UIElement content, string theme, int width)
    {
        var host = new Border { Child = content, Width = width, Padding = new Thickness(24) };
        foreach (string resource in new[] { $"Colors.{theme}", "Typography", "Components", "SharedStyles" })
            host.Resources.MergedDictionaries.Add(new ResourceDictionary
            { Source = new Uri($"/UltronDefender;component/Resources/Themes/{resource}.xaml", UriKind.Relative) });
        host.SetResourceReference(Border.BackgroundProperty, "BrushAppBg");
        return host;
    }

    private static void Layout(FrameworkElement host, int width)
    {
        for (int i = 0; i < 3; i++)
        {
            host.Measure(new Size(width, double.PositiveInfinity));
            host.Arrange(new Rect(0, 0, width, Math.Ceiling(host.DesiredSize.Height)));
            host.UpdateLayout(); Pump();
        }
    }

    private static void SaveRender(FrameworkElement host, string theme, int width, int dpi)
    {
        var bitmap = new RenderTargetBitmap(width * dpi / 96, (int)Math.Ceiling(host.ActualHeight * dpi / 96), dpi, dpi, PixelFormats.Pbgra32);
        bitmap.Render(host);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        string directory = Path.Combine(AppContext.BaseDirectory, "PlainUiPreview"); Directory.CreateDirectory(directory);
        using var stream = File.Create(Path.Combine(directory, $"plain-dashboard-{theme}-{width}-{dpi}.png"));
        encoder.Save(stream); Assert.True(stream.Length > 500);
    }

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

    private static void Pump()
    {
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
    }

    private static void RunSta(Action action)
    {
        Exception? error = null;
        var thread = new Thread(() => { try { action(); } catch (Exception ex) { error = ex; }
            finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); } }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA); thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(20)), "Inert UI test exceeded its budget.");
        if (error != null) ExceptionDispatchInfo.Capture(error).Throw();
    }

    private sealed class RecordingCommand : ICommand
    {
        public int Count { get; private set; }
        public event EventHandler? CanExecuteChanged { add { } remove { } }
        public bool CanExecute(object? parameter) => true;
        public void Execute(object? parameter) => Count++;
    }
}
