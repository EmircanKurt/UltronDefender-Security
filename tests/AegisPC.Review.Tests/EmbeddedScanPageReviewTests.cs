using System.IO;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Xml.Linq;
using AegisPC.App.Controls;
using AegisPC.App.ViewModels;
using AegisPC.App.Views;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Renders the compiled main scanner page without starting the application or a security service.</summary>
public sealed class EmbeddedScanPageReviewTests
{
    /// <summary>Idle, active and final states are embedded in the page and the finite viewport keeps active controls reachable.</summary>
    [Theory]
    [InlineData("Light", "Idle")] [InlineData("Dark", "Idle")]
    [InlineData("Light", "Active")] [InlineData("Dark", "Active")]
    [InlineData("Light", "Final")] [InlineData("Dark", "Final")]
    public void CompiledPageRendersAllStates(string theme, string state) => Sta(() =>
    {
        var store = new AegisPC.App.Services.ScanReportHistoryStore(Path.Combine(Path.GetTempPath(), "UltronEmptyHistory-" + Guid.NewGuid().ToString("N") + ".json"));
        var vm = new ScanViewModel(reportHistoryStore: store, presentScanner: () => throw new InvalidOperationException("Rendering cannot request foreground presentation."));
        vm.IsScanning = state == "Active"; vm.IsNotScanning = state != "Active"; vm.IsScanFinishedView = state == "Final";
        vm.ScanStatusText = "Ekran dışı önizleme — gerçek tarama değildir.";
        vm.CurrentFile = @"C:\lab-fixture\example.txt";
        var page = new ScanView(vm);
        var frame = new Frame { Content = page, NavigationUIVisibility = System.Windows.Navigation.NavigationUIVisibility.Hidden };
        var host = new Border { Child = frame, Width = 940, Height = 776 };
        foreach (string resource in new[] { "Colors." + theme, "Typography", "Components", "SharedStyles" })
            page.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri($"/UltronDefender;component/Resources/Themes/{resource}.xaml", UriKind.Relative) });
        // Frame navigation deliberately skips parent resources. Model the actual application palette on the page itself.
        page.Resources.MergedDictionaries.Insert(0, (ResourceDictionary)System.Windows.Markup.XamlReader.Parse(
            $"<ResourceDictionary xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' xmlns:ui='http://schemas.lepo.co/wpfui/2022/xaml'><ResourceDictionary.MergedDictionaries><ui:ThemesDictionary Theme='{theme}'/><ui:ControlsDictionary/></ResourceDictionary.MergedDictionaries></ResourceDictionary>"));
        for (int i=0;i<4;i++) { host.Measure(new Size(940,776)); host.Arrange(new Rect(0,0,940,776)); host.UpdateLayout(); Pump(); }
        var chooser = Descendants<ClassicScanSurface>(page).Single();
        var active = Descendants<ActiveScanSurface>(page).Single();
        Assert.Equal(state == "Idle" ? Visibility.Visible : Visibility.Collapsed, chooser.Visibility);
        Assert.Equal(state == "Active" ? Visibility.Visible : Visibility.Collapsed, active.Visibility);
        Assert.IsType<SolidColorBrush>(page.Background);
        Assert.IsType<SolidColorBrush>(chooser.Foreground);
        var foreground = ((SolidColorBrush)chooser.Foreground).Color;
        Assert.True(theme == "Light" ? foreground.R < 100 : foreground.R > 200);
        if (state == "Active")
        {
            foreach (string name in new[] { "PauseButton", "CancelButton" })
            {
                var button = (Button)active.FindName(name);
                var bounds = button.TransformToAncestor(host).TransformBounds(new Rect(0,0,button.ActualWidth,button.ActualHeight));
                Assert.True(button.IsEnabled);
                Assert.True(bounds.Bottom <= 776 && bounds.Left >= 0 && bounds.Right <= 940);
            }
        }
        var bitmap = new RenderTargetBitmap(940,776,96,96,PixelFormats.Pbgra32); bitmap.Render(host);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        string folder = Path.Combine(AppContext.BaseDirectory,"EmbeddedScanPreview"); Directory.CreateDirectory(folder);
        using var stream = File.Create(Path.Combine(folder,$"{theme}-{state}.png")); encoder.Save(stream);
    });

    /// <summary>Every actual sidebar item explicitly opts into the custom readable template; normal launch selects the scanner.</summary>
    [Fact]
    public void ActualShellUsesExplicitSidebarAndScannerLanding()
    {
        string root = Repository();
        var doc = XDocument.Load(Path.Combine(root,"src/AegisPC.App/MainWindow.xaml"));
        XNamespace ui = "http://schemas.lepo.co/wpfui/2022/xaml";
        foreach (var item in doc.Descendants(ui + "NavigationViewItem"))
            Assert.Equal("{StaticResource UltronSidebarItemStyle}", (string?)item.Attribute("Style"));
        foreach (var icon in doc.Descendants(ui + "SymbolIcon"))
            Assert.Equal("{DynamicResource BrushSidebarTextSecondary}", (string?)icon.Attribute("Foreground"));
        string landing = File.ReadAllText(Path.Combine(root,"src/AegisPC.App/MainWindow.xaml.cs"));
        Assert.Contains("RootNavigation.Navigate(typeof(ScanView));", landing);
        Assert.DoesNotContain("RootNavigation.Navigate(typeof(DashboardView));", landing);
        string sync = File.ReadAllText(Path.Combine(root,"src/AegisPC.App/ViewModels/ScanViewModel.Sync.cs"));
        Assert.DoesNotContain("ShowScanWindow",sync); Assert.DoesNotContain("ShowScanner",sync);
    }

    private static string Repository()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName,"AegisPC.sln"))) return dir.FullName;
        throw new DirectoryNotFoundException();
    }
    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (int i=0;i<VisualTreeHelper.GetChildrenCount(parent);i++)
        { var child = VisualTreeHelper.GetChild(parent,i); if (child is T match) yield return match; foreach (var item in Descendants<T>(child)) yield return item; }
    }
    private static void Pump()
    {
        var frame = new DispatcherFrame(); Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle,new Action(() => frame.Continue=false)); Dispatcher.PushFrame(frame);
    }
    private static void Sta(Action action)
    {
        Exception? error = null; var thread = new Thread(() => { try { action(); } catch (Exception ex) { error=ex; } finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); } }) { IsBackground=true };
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); Assert.True(thread.Join(TimeSpan.FromSeconds(20)));
        if (error != null) ExceptionDispatchInfo.Capture(error).Throw();
    }
}
