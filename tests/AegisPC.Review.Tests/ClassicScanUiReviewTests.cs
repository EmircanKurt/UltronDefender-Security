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
using System.Windows.Markup;
using System.Xml.Linq;
using AegisPC.App.Controls;
using AegisPC.App.Helpers;
using AegisPC.App.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Off-screen native UI tests using fake commands only; never launches scans, Ultron services or protection actions.</summary>
public sealed class ClassicScanUiReviewTests
{
    /// <summary>At normal window size the actual chooser/history fit without page scrolling in both palettes.</summary>
    [Theory]
    [InlineData("Light")] [InlineData("Dark")]
    public void FiniteReferenceLayoutIncludesScopeAndHistory(string theme) => RunSta(() =>
    {
        var surface = new ClassicScanSurface { DataContext = Fixture() };
        var host = Host(surface, theme, 940);
        for (int i = 0; i < 4; i++) { host.Measure(new Size(940, 776)); host.Arrange(new Rect(0,0,940,776)); host.UpdateLayout(); Pump(); }
        var scope = (Border)surface.FindName("ScopePanel");
        var selection = (Border)surface.FindName("SelectionPanel");
        var table = (DataGrid)surface.FindName("HistoryTable");
        var scroll = (ScrollViewer)surface.FindName("ContentScroll");
        Assert.Equal(0, Grid.GetRow(scope)); Assert.Equal(1, Grid.GetColumn(scope));
        Assert.True(scope.ActualWidth > 300 && selection.ActualWidth > 450);
        SaveRender(host, theme + "-finite-debug", 940, 96);
        Assert.True(scroll.ScrollableHeight < 1, $"Default viewport must fit: overflow={scroll.ScrollableHeight}, extent={scroll.ExtentHeight}, viewport={scroll.ViewportHeight}, choice={selection.ActualHeight}, scope={scope.ActualHeight}.");
        var bounds = table.TransformToAncestor(host).TransformBounds(new Rect(0,0,table.ActualWidth,table.ActualHeight));
        Assert.True(bounds.Bottom <= 776);
        SaveRender(host, theme + "-finite", 940, 96);
        SaveShellPreview(host, theme);
    });

    private static void SaveShellPreview(Border page, string theme)
    {
        // Parse the real sidebar item template rather than painting a substitute navigation design.
        string root = FindRepository();
        var doc = XDocument.Load(Path.Combine(root, "src/AegisPC.App/MainWindow.xaml"));
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace x = "http://schemas.microsoft.com/winfx/2006/xaml";
        var styleElement = doc.Descendants(wpf + "Style").Single(e => (string?)e.Attribute(x + "Key") == "UltronSidebarItemStyle");
        styleElement.SetAttributeValue(XNamespace.Xmlns + "ui", "http://schemas.lepo.co/wpfui/2022/xaml");
        string markup = styleElement.ToString().Replace("{StaticResource FontSans}", "Segoe UI");
        var style = (Style)XamlReader.Parse(markup);
        var body = new Grid(); body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(240) }); body.ColumnDefinitions.Add(new ColumnDefinition());
        var sidebar = new StackPanel(); sidebar.SetResourceReference(Panel.BackgroundProperty, "BrushSidebarBg");
        sidebar.Children.Add(new TextBlock { Text = "ULTRON\nDefender", FontFamily = new FontFamily("Segoe UI"), FontSize = 24, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(System.Windows.Media.Colors.White), Margin = new Thickness(24,30,10,45) });
        foreach (string label in new[] { "Genel bakış", "Tarayıcı", "Korumalar", "Karantina ve olaylar", "Browser Defender", "Süreç Yöneticisi", "Sistem tanılama" })
            sidebar.Children.Add(new Wpf.Ui.Controls.NavigationViewItem { Content = label, Style = style, IsActive = label == "Tarayıcı", Icon = new Wpf.Ui.Controls.SymbolIcon { Symbol = label == "Tarayıcı" ? Wpf.Ui.Controls.SymbolRegular.Search24 : Wpf.Ui.Controls.SymbolRegular.Shield24 } });
        body.Children.Add(sidebar); body.Children.Add(page); Grid.SetColumn(page, 1);
        var shell = Host(body, theme, 1180); shell.Padding = new Thickness(0);
        shell.Resources.MergedDictionaries.Insert(0, (ResourceDictionary)XamlReader.Parse(
            $"<ResourceDictionary xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' xmlns:ui='http://schemas.lepo.co/wpfui/2022/xaml'><ResourceDictionary.MergedDictionaries><ui:ThemesDictionary Theme='{theme}'/><ui:ControlsDictionary/></ResourceDictionary.MergedDictionaries></ResourceDictionary>"));
        for (int i=0;i<4;i++) { shell.Measure(new Size(1180,776)); shell.Arrange(new Rect(0,0,1180,776)); shell.UpdateLayout(); Pump(); }
        foreach (string state in new[] { "", "PointerOver", "Pressed", "Selected" })
        {
            string fg = "NavigationViewItemForeground" + state;
            string bg = state.Length == 0 ? "BrushSidebarBg" : "NavigationViewItemBackground" + state;
            Assert.True(Contrast(Brush(shell, fg), Brush(shell, bg)) >= 4.5, theme + "/native-sidebar/" + state);
        }
        var active = sidebar.Children.OfType<Wpf.Ui.Controls.NavigationViewItem>().Single(item => item.IsActive);
        Assert.True(Contrast(((SolidColorBrush)active.Foreground).Color, Brush(shell, "BrushShellSidebarActive")) >= 4.5);
        SaveRender(shell, theme + "-shell-fixture", 1180, 96);
    }

    private static string FindRepository()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName,"src/AegisPC.App/MainWindow.xaml"))) return directory.FullName;
        throw new DirectoryNotFoundException("Review source tree unavailable.");
    }

    /// <summary>Checks approved theme layouts, text bounds, neutral contrast and keyboard targets at multiple sizes and DPIs.</summary>
    [Theory]
    [InlineData("Light", 900, 96)] [InlineData("Dark", 900, 96)]
    [InlineData("Light", 720, 144)] [InlineData("Dark", 720, 144)]
    [InlineData("Light", 360, 192)] [InlineData("Dark", 360, 192)]
    public void LayoutIsReadable(string theme, int width, int dpi) => RunSta(() =>
    {
        var surface = new ClassicScanSurface { DataContext = Fixture() };
        var host = Host(surface, theme, width); Layout(host, width);
        Assert.Equal(Visibility.Visible, ((Border)surface.FindName("ScopePanel")).Visibility);
        Assert.Equal(Visibility.Visible, ((Border)surface.FindName("SelectionPanel")).Visibility);
        var table=(DataGrid)surface.FindName("HistoryTable");
        Assert.Equal(Visibility.Visible, table.Columns[2].Visibility);
        Assert.Equal(width - 48 < 700 ? 1 : 0, Grid.GetRow((Border)surface.FindName("ScopePanel")));
        foreach (var text in Descendants<TextBlock>(surface).Where(t => t.ActualWidth > 0 && t.ActualHeight > 0))
        {
            var bounds = text.TransformToAncestor(host).TransformBounds(new Rect(0, 0, text.ActualWidth, text.ActualHeight));
            Assert.True(bounds.Left >= -.5 && bounds.Right <= width + .5, $"Text escaped viewport: {text.Text}");
            Assert.False(text.HasAnimatedProperties);
        }
        foreach (var button in Descendants<Button>(surface).Where(b => b.ActualWidth > 0 && b.ActualHeight > 0))
        {
            Assert.NotNull(button.Command); Assert.True(button.Focusable); Assert.True(button.IsTabStop);
            var bounds = button.TransformToAncestor(host).TransformBounds(new Rect(0, 0, button.ActualWidth, button.ActualHeight));
            Assert.True(bounds.Left >= -.5 && bounds.Right <= width + .5, $"Button escaped viewport: {button.Content}");
        }
        foreach (string foreground in new[] { "BrushTextPrimary", "BrushTextSecondary", "BrushTextMuted" })
            foreach (string background in new[] { "BrushAppBg", "BrushCardBg" })
                Assert.True(Contrast(Brush(host, foreground), Brush(host, background)) >= 4.5, foreground + "/" + background);
        Assert.NotEqual(Brush(host, "BrushAppBg"), Brush(host, "BrushSidebarBg"));
        foreach (string foreground in new[] { "BrushSidebarTextPrimary", "BrushSidebarTextSecondary" })
            Assert.True(Contrast(Brush(host, foreground), Brush(host, "BrushSidebarBg")) >= 4.5);
        var primary = (Button)surface.FindName("StartSelectedButton");
        Assert.True(Contrast(((SolidColorBrush)primary.Foreground).Color, ((SolidColorBrush)primary.Background).Color) >= 4.5);
        SaveRender(host, theme, width, dpi);
    });

    /// <summary>Only an explicit start invokes the selected supplied command; selecting or switching themes invokes nothing.</summary>
    [Fact]
    public void LightSelectionRoutesExistingCommandsWithoutAutoStart() => RunSta(() =>
    {
        var quick = new RecordingCommand(); var full = new RecordingCommand(); var custom = new RecordingCommand();
        var surface = new ClassicScanSurface { DataContext = Fixture(quick, full, custom) };
        var host = Host(surface, "Light", 900); Layout(host, 900);
        var start = (Button)surface.FindName("StartSelectedButton");
        Assert.Same(quick, start.Command);
        ((RadioButton)surface.FindName("FullChoice")).IsChecked = true; Pump();
        Assert.Equal(ScanType.Full, surface.SelectedScanType); Assert.Same(full, start.Command);
        Assert.Equal(0, quick.Count + full.Count + custom.Count);
        Invoke(start); Assert.Equal(1, full.Count);
        ((RadioButton)surface.FindName("CustomChoice")).IsChecked = true; Pump();
        Assert.Same(custom, start.Command); Assert.Equal("Taramayı başlat", start.Content);
        Invoke(start); Assert.Equal(1, custom.Count);
        host.Resources.MergedDictionaries[0] = Colors("Dark"); Layout(host, 900);
        Assert.Equal(Visibility.Visible, ((Border)surface.FindName("ScopePanel")).Visibility);
        host.Resources.MergedDictionaries[0] = Colors("Light"); Layout(host, 900);
        Assert.Equal(Visibility.Visible, ((Border)surface.FindName("SelectionPanel")).Visibility);
        Assert.Equal(ScanType.Custom, surface.SelectedScanType); Assert.Same(custom, start.Command);
        Assert.Equal(2, quick.Count + full.Count + custom.Count);
    });

    /// <summary>Picking a folder selects custom scope without starting any scan.</summary>
    [Fact]
    public void FolderPickerSelectsCustomWithoutStarting()
    {
        RunSta(() =>
        {
            var quick = new RecordingCommand(); var full = new RecordingCommand(); var custom = new RecordingCommand();
            var surface = new ClassicScanSurface { DataContext = Fixture(quick, full, custom) };
            var host = Host(surface, "Light", 900); Layout(host, 900);
            Invoke((Button)surface.FindName("FolderPickerButton"));
            Assert.Equal(ScanType.Custom, surface.SelectedScanType);
            Assert.Same(custom, ((Button)surface.FindName("StartSelectedButton")).Command);
            Assert.Equal(0, quick.Count + full.Count + custom.Count);
        });
    }

    /// <summary>Dark theme uses the same selected-scope start action as light theme.</summary>
    [Fact]
    public void DarkRowsKeepThreeDistinctActions() => RunSta(() =>
    {
        var quick = new RecordingCommand(); var full = new RecordingCommand(); var custom = new RecordingCommand();
        var surface = new ClassicScanSurface { DataContext = Fixture(quick, full, custom) };
        var host = Host(surface, "Dark", 900); Layout(host, 900);
        var start = (Button)surface.FindName("StartSelectedButton");
        Invoke(start);
        ((RadioButton)surface.FindName("FullChoice")).IsChecked = true; Pump(); Invoke(start);
        Assert.Equal("Yerel diskler", ((TextBlock)surface.FindName("ScopeTitle")).Text);
        ((RadioButton)surface.FindName("CustomChoice")).IsChecked = true; Pump(); Invoke(start);
        Assert.Equal("Seçilen hedef", ((TextBlock)surface.FindName("ScopeTitle")).Text);
        Assert.Equal(1, quick.Count); Assert.Equal(1, full.Count); Assert.Equal(1, custom.Count);
    });

    /// <summary>Both presentations disable new scan requests while an existing scan runs; progress remains truthful.</summary>
    [Theory]
    [InlineData("Light")] [InlineData("Dark")]
    public void RunningScanDisablesNewScanActions(string theme) => RunSta(() =>
    {
        var surface = new ClassicScanSurface { DataContext = Fixture(scanning: true) };
        var host = Host(surface, theme, 900); Layout(host, 900);
        foreach (string name in new[] { "StartSelectedButton", "FolderPickerButton" })
            Assert.False(((Button)surface.FindName(name)).IsEnabled);
        Assert.Contains(Descendants<TextBlock>(surface), t => t.Text == "Kapsam");
    });

    /// <summary>History errors are visible, not rewritten as clean or empty, and report summaries bind real supplied data.</summary>
    [Fact]
    public void HistoryStateIsNotInvented() => RunSta(() =>
    {
        var surface = new ClassicScanSurface { DataContext = Fixture(historyError: true) };
        var host = Host(surface, "Light", 900); Layout(host, 900);
        Assert.Contains(Descendants<TextBlock>(surface), t => t.Text == "Rapor geçmişi okunamadı.");
        Assert.Contains(Descendants<TextBlock>(surface), t => t.Text == "Başarısız");
        Assert.DoesNotContain(Descendants<TextBlock>(surface), t => t.Text == "Sisteminiz güvende");
    });

    /// <summary>Wheel input over a child button scrolls the page in a small viewport, with no horizontal overflow.</summary>
    [Theory]
    [InlineData("Light")] [InlineData("Dark")]
    public void WheelScrollingSurvivesNewLayout(string theme) => RunSta(() =>
    {
        var surface = new ClassicScanSurface { DataContext = Fixture() };
        var scroll = new ScrollViewer { Content = surface, Width = 360, Height = 350, CanContentScroll = false,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
        WheelScrollHelper.SetEnableRootRedirect(scroll, true);
        var host = Host(scroll, theme, 408); Layout(host, 408);
        Assert.True(scroll.ScrollableHeight > 100);
        var button = (Button)surface.FindName("StartSelectedButton");
        button.RaiseEvent(new MouseWheelEventArgs(Mouse.PrimaryDevice, 0, -120) { RoutedEvent = Mouse.PreviewMouseWheelEvent });
        Pump(); scroll.UpdateLayout(); Assert.True(scroll.VerticalOffset > 0); Assert.Equal(0, scroll.HorizontalOffset);
    });

    private static object Fixture(RecordingCommand? quick = null, RecordingCommand? full = null, RecordingCommand? custom = null, bool scanning = false, bool historyError = false) => new
    {
        StartQuickScanCommand = quick ?? new(), StartFullScanCommand = full ?? new(), StartCustomScanCommand = custom ?? new(),
        StartSelectedCustomScanCommand = custom ?? new(), SelectCustomFolderCommand = new RecordingCommand(), SelectedCustomFolder = "",
        OpenSchedulerCommand = new RecordingCommand(), OpenReportsCommand = new RecordingCommand(),
        OpenActiveScanWindowCommand = new RecordingCommand(), RefreshReportsCommand = new RecordingCommand(),
        IsNotScanning = !scanning, ScanStatusText = scanning ? "Tarama devam ediyor." : "Taramaya hazır.", RemainingEtaFormatted = "",
        OpenScanWindowButtonText = "Tarayıcı penceresini aç",
        ReportHistoryStatus = historyError ? "Rapor geçmişi okunamadı." : "Önizleme verisi — gerçek tarama sonucu değildir.",
        ReportHistory = new ObservableCollection<ScanReportRecord> { new() { Result = new ScanResult { Status = ScanStatus.Failed, ScannedFiles = 12, FailedFiles = 1, ScanType = ScanType.Quick, StartedAt = new DateTime(2026,10,8,15,20,0,DateTimeKind.Utc), ElapsedMs = 62000 } } }
    };

    private static Border Host(UIElement surface, string theme, int width)
    {
        var host = new Border { Child = surface, Width = width, Padding = new Thickness(24) };
        host.Resources.MergedDictionaries.Add(Colors(theme));
        foreach (string resource in new[] { "Typography", "Components", "SharedStyles" })
            host.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri($"/UltronDefender;component/Resources/Themes/{resource}.xaml", UriKind.Relative) });
        host.SetResourceReference(Border.BackgroundProperty, "BrushAppBg");
        return host;
    }

    private static ResourceDictionary Colors(string theme) => new() { Source = new Uri($"/UltronDefender;component/Resources/Themes/Colors.{theme}.xaml", UriKind.Relative) };
    private static Color Brush(FrameworkElement host, string key) => ((SolidColorBrush)host.FindResource(key)).Color;
    private static void Invoke(Button button) { ((IInvokeProvider)new ButtonAutomationPeer(button)).Invoke(); Pump(); }
    private static void Layout(FrameworkElement host, int width)
    {
        for (int i = 0; i < 3; i++) { host.Measure(new Size(width, double.PositiveInfinity)); host.Arrange(new Rect(0, 0, width, Math.Ceiling(host.DesiredSize.Height))); host.UpdateLayout(); Pump(); }
    }
    private static void SaveRender(FrameworkElement host, string theme, int width, int dpi)
    {
        var bitmap = new RenderTargetBitmap(width * dpi / 96, (int)Math.Ceiling(host.ActualHeight * dpi / 96), dpi, dpi, PixelFormats.Pbgra32); bitmap.Render(host);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        string directory = Path.Combine(AppContext.BaseDirectory, "ClassicUiPreview"); Directory.CreateDirectory(directory);
        using var stream = File.Create(Path.Combine(directory, $"classic-scan-{theme}-{width}-{dpi}.png")); encoder.Save(stream); Assert.True(stream.Length > 500);
    }
    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        { var child = VisualTreeHelper.GetChild(parent, i); if (child is T typed) yield return typed; foreach (var descendant in Descendants<T>(child)) yield return descendant; }
    }
    private static double Contrast(Color a, Color b)
    {
        static double L(Color c) { static double Linear(byte x) { double v = x / 255d; return v <= .04045 ? v / 12.92 : Math.Pow((v + .055) / 1.055, 2.4); } return .2126 * Linear(c.R) + .7152 * Linear(c.G) + .0722 * Linear(c.B); }
        return (Math.Max(L(a), L(b)) + .05) / (Math.Min(L(a), L(b)) + .05);
    }
    private static void Pump()
    {
        var frame = new DispatcherFrame(); Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false)); Dispatcher.PushFrame(frame);
    }
    private static void RunSta(Action action)
    {
        Exception? error = null;
        var thread = new Thread(() => { try { action(); } catch (Exception ex) { error = ex; } finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); } }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); Assert.True(thread.Join(TimeSpan.FromSeconds(20)), "Off-screen UI test exceeded budget.");
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
