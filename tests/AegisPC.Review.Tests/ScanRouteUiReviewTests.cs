using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text.Json;
using System.IO;
using System.Reflection;
using System.Xml.Linq;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Markup;
using System.Windows.Threading;
using AegisPC.App.Controls;
using AegisPC.App.Helpers;
using AegisPC.App.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert native vector/render/lifecycle tests; no real scans, malware, services or protection mutations.</summary>
public sealed class ScanRouteUiReviewTests
{
    /// <summary>Every missing lifecycle prerequisite prevents optional animation, including stale and unknown activity.</summary>
    [Theory]
    [InlineData(false,false,true,true,true,false,true,0)] [InlineData(true,true,true,true,true,false,true,0)]
    [InlineData(true,false,false,true,true,false,true,0)] [InlineData(true,false,true,false,true,false,true,0)]
    [InlineData(true,false,true,true,false,false,true,0)] [InlineData(true,false,true,true,true,true,true,0)]
    [InlineData(true,false,true,true,true,false,false,0)] [InlineData(true,false,true,true,true,false,true,15)]
    [InlineData(true,false,true,true,true,false,true,double.NaN)]
    public void UnsafeEnvironmentStopsMotion(bool running, bool paused, bool loaded, bool visible, bool ownerVisible, bool minimized, bool allowed, double age) =>
        Assert.False(ScanRouteMotionPolicy.CanAnimate(running,paused,loaded,visible,ownerVisible,minimized,allowed,age));

    /// <summary>Fresh active state permits bounded slow motion without turning it into a security verdict.</summary>
    [Fact]
    public void MotionIsSlowFiniteAndBounded()
    {
        Assert.True(ScanRouteMotionPolicy.CanAnimate(true,false,true,true,true,false,true,14.9));
        Assert.Equal(TimeSpan.FromMilliseconds(50), ScanRouteMotionPolicy.UpdateInterval);
        double phase = 0;
        for (int i=0;i<160;i++) { phase=ScanRouteMotionPolicy.Advance(phase,.05); Assert.InRange(ScanRouteMotionPolicy.Offset(phase),0,152); }
        Assert.True(phase < .000001 || phase > .999999);
        Assert.Equal(0,ScanRouteMotionPolicy.Advance(double.NaN,.05));
        Assert.Equal(0,ScanRouteMotionPolicy.Offset(double.PositiveInfinity));
        Assert.Equal(.03125,ScanRouteMotionPolicy.Advance(0,999));
    }

    /// <summary>Unshown window/unload/detach are exercised without launching the application or starting a UI timer.</summary>
    [Fact]
    public void UnloadReleasesSubscriptionsAndMotionRemainsOptIn() => Sta(() =>
    {
        var route = new ScanRouteVisual { IsRunning=true, CurrentFile="fixture.txt", ActivityStamp="1" };
        Assert.False(route.IsAnimating);
        var window = new Window { Content=route };
        for (int i=0;i<3;i++)
        {
            route.RaiseEvent(new RoutedEventArgs(FrameworkElement.LoadedEvent));
            Assert.True((bool)typeof(ScanRouteVisual).GetField("_attached",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(route)!);
            route.IsPaused=true; Assert.False(route.IsAnimating); route.IsPaused=false;
            route.IsMotionEnabled=false; Assert.False(route.IsAnimating);
            route.RaiseEvent(new RoutedEventArgs(FrameworkElement.UnloadedEvent));
            Assert.False((bool)typeof(ScanRouteVisual).GetField("_attached",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(route)!);
        }
        window.Close(); Assert.False(route.IsAnimating);
    });

    /// <summary>Native active scan data stays readable in both themes and a narrow, scrollable viewport.</summary>
    [Theory]
    [InlineData("Dark",960)] [InlineData("Light",960)] [InlineData("Dark",420)] [InlineData("Light",420)]
    public void ActiveScanRendersRealBoundFieldsAndResponsiveSections(string theme, int width) => Sta(() =>
    {
        var command=new Command();
        var surface=new ActiveScanSurface { DataContext = new
        {
            IsScanning=true,IsPaused=false,CurrentFile="C:\\Test\\örnek.dll",ScanStatusText="İçerik inceleniyor",ScannedItemsFormatted="63",
            ScanDurationFormatted="0 dk 08 sn",ScannedBreakdownFormatted="63 yeni tarandı",ActiveResourceProfileText="Test profili",
            FailedCount=14,TimedOutCount=0,PauseButtonText="Duraklat",TogglePauseResumeCommand=command,CancelScanCommand=command,
            DetectionsCount=0,FindingBreakdownText="0 doğrulanmış • 0 inceleme",CpuAndRamFormatted="CPU: ölçülmedi • RAM: ölçülmedi",
            ProgressPercentage=42d,RemainingEtaFormatted="Hesaplanıyor..."
        }};
        var host=Host(surface,theme,width); Layout(host,width);
        Assert.Equal(width<620?1:0,Grid.GetRow((StackPanel)surface.FindName("DetailPanel")));
        Assert.Equal(42,((ProgressBar)surface.FindName("ScanProgress")).Value);
        Assert.Contains(Texts(surface),t=>t.Text=="İçerik inceleniyor");
        Assert.Contains(Texts(surface),t=>t.Text=="63");
        var route=(ScanRouteVisual)surface.FindName("RouteVisual"); Assert.False(route.IsAnimating);
        Assert.True(route.IsRunning); Assert.Equal("63",route.ActivityStamp);
        var button=(Button)surface.FindName("PauseButton");
        ((IInvokeProvider)new ButtonAutomationPeer(button)).Invoke(); Pump(); Assert.Equal(1,command.Count);
        foreach (var text in Texts(surface).Where(t=>t.ActualWidth>0 && t.ActualHeight>0))
        {
            var bounds=text.TransformToAncestor(host).TransformBounds(new Rect(0,0,text.ActualWidth,text.ActualHeight));
            Assert.True(bounds.Left>=-.5 && bounds.Right<=width+.5,$"Overflow: {text.Text}");
        }
        Capture(host,$"active-{theme}-{width}",width);
    });

    /// <summary>Report columns use actual recorded data; missing timestamps/durations and unknown kinds are never invented.</summary>
    [Fact]
    public void HistoryFormattingKeepsRecordedValuesAndLegacyUnknown()
    {
        var report=new ScanReportRecord {Result=new ScanResult {ScanType=ScanType.Custom,CustomPath="C:\\Test",ElapsedMs=119000}};
        Assert.Equal("1 dk 59 sn",report.DurationText); Assert.Equal("Özel tarama",report.ScanTypeText); Assert.Equal("C:\\Test",report.TargetText);
        report.Result.ElapsedMs=0; report.Result.ScanType=(ScanType)999; report.Result.CustomPath=null;
        Assert.Equal("Kaydedilmedi",report.DurationText); Assert.Equal("Bilinmeyen",report.ScanTypeText); Assert.Equal("Konum kaydedilmedi",report.TargetText); Assert.Contains("kaydedilmedi",report.DateText);
    }

    /// <summary>Choosers share a real table, keep selection separate, and the separate idle window no longer contains old cards/laser.</summary>
    [Fact]
    public void ChooserUsesHistoryTableAndInertFolderSelection() => Sta(() =>
    {
        var command=new Command();
        var surface=new ClassicScanSurface {DataContext=new
        {
            IsNotScanning=true,StartQuickScanCommand=command,StartFullScanCommand=command,StartCustomScanCommand=command,StartSelectedCustomScanCommand=command,
            SelectCustomFolderCommand=command,SelectedCustomFolder="",OpenActiveScanWindowCommand=command,OpenReportsCommand=command,OpenSchedulerCommand=command,RefreshReportsCommand=command,
            ReportHistoryStatus="Bu kullanıcı için henüz kaydedilmiş tarama yok.",ReportHistory=new ObservableCollection<ScanReportRecord>()
        }};
        var host=Host(surface,"Light",900); Layout(host,900);
        Assert.Empty(((DataGrid)surface.FindName("HistoryTable")).Items); Assert.Equal(0,command.Count);
        ((IInvokeProvider)new ButtonAutomationPeer((Button)surface.FindName("FolderPickerButton"))).Invoke(); Pump(); Assert.Equal(1,command.Count);
        string source=File.ReadAllText(Path.Combine(Root(),"src/AegisPC.App/Views/ActiveScanWindow.xaml"));
        Assert.Contains("controls:ClassicScanSurface",source); Assert.Contains("controls:ActiveScanSurface",source); Assert.DoesNotContain("LaserLine",source); Assert.DoesNotContain("<UniformGrid",source);
    });

    private static string Root() { var p=new DirectoryInfo(AppContext.BaseDirectory); while(p!=null&&!File.Exists(Path.Combine(p.FullName,"AegisPC.sln")))p=p.Parent; return p?.FullName??throw new DirectoryNotFoundException(); }
    /// <summary>Renders real shell brand/menu-template fragments with inert scan commands and checks native click/selection behavior.</summary>
    [Theory]
    [InlineData("Dark")] [InlineData("Light")]
    public void ApprovedShellFragmentsRenderWithWorkingNativeMenu(string theme) => Sta(() =>
    {
        var document=XDocument.Load(Path.Combine(Root(),"src/AegisPC.App/MainWindow.xaml"));
        XNamespace ui="http://schemas.lepo.co/wpfui/2022/xaml";
        XNamespace x="http://schemas.microsoft.com/winfx/2006/xaml";
        XNamespace w="http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        var style=new XElement(document.Descendants(w+"Style").First(s=>s.Attribute("TargetType")?.Value=="{x:Type ui:NavigationViewItem}"));
        var brand=new XElement(document.Descendants(w+"Border").First(s=>s.Attribute(x+"Name")?.Value=="BrandHeader"));
        string Wrap(XElement element)=>new XElement(w+"ResourceDictionary",new XAttribute("xmlns",w.NamespaceName),new XAttribute(XNamespace.Xmlns+"x",x.NamespaceName),new XAttribute(XNamespace.Xmlns+"ui",ui.NamespaceName),
            new XElement(w+"ResourceDictionary.MergedDictionaries",new XElement(w+"ResourceDictionary",new XAttribute("Source","/UltronDefender;component/Resources/Themes/Typography.xaml"))),element).ToString();
        var shell=new Grid(); shell.ColumnDefinitions.Add(new ColumnDefinition {Width=new GridLength(240)}); shell.ColumnDefinitions.Add(new ColumnDefinition());
        var host=Host(shell,theme,1180); host.Padding=new Thickness(0);
        host.Resources.MergedDictionaries.Insert(0,(ResourceDictionary)XamlReader.Parse($"<ResourceDictionary xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' xmlns:ui='http://schemas.lepo.co/wpfui/2022/xaml'><ResourceDictionary.MergedDictionaries><ui:ThemesDictionary Theme='{theme}'/><ui:ControlsDictionary/></ResourceDictionary.MergedDictionaries></ResourceDictionary>"));
        shell.Resources.MergedDictionaries.Add((ResourceDictionary)XamlReader.Parse(Wrap(style)));
        // A resource key is required for the cloned header, never an application startup object.
        var keyedBrand=new XElement(brand); keyedBrand.SetAttributeValue(x+"Key","Header"); keyedBrand.Attribute(x+"Name")?.Remove();
        foreach(var named in keyedBrand.Descendants().Attributes(x+"Name").ToArray())named.Remove();
        var brandDictionary=(ResourceDictionary)XamlReader.Parse(Wrap(keyedBrand));
        var sidebar=new StackPanel(); sidebar.Children.Add((Border)brandDictionary["Header"]);
        // The vendor's OnClick requires a NavigationView ancestor even for a commandless item.
        var navigation=new Wpf.Ui.Controls.NavigationView {PaneHeader=sidebar,OpenPaneLength=240,IsPaneOpen=true,PaneDisplayMode=Wpf.Ui.Controls.NavigationViewPaneDisplayMode.Left,IsBackButtonVisible=Wpf.Ui.Controls.NavigationViewBackButtonVisible.Collapsed,IsPaneToggleVisible=false,HeaderVisibility=Visibility.Collapsed};
        var pane=new Border {Child=navigation}; pane.SetResourceReference(Border.BackgroundProperty,"BrushSidebarBg"); shell.Children.Add(pane);
        MenuProbe? selected=null;
        foreach(string label in new[] {"Genel bakış","Tarayıcı","Korumalar","Karantina ve olaylar","Browser Defender","Süreç Yöneticisi","Sistem tanılama","Ayarlar"})
        {
            var item=new MenuProbe {Content=label,Icon=new Wpf.Ui.Controls.SymbolIcon(Wpf.Ui.Controls.SymbolRegular.Search24),IsActive=label=="Tarayıcı",Style=(Style)shell.FindResource("UltronSidebarItemStyle")};
            sidebar.Children.Add(item); if(item.IsActive)selected=item;
        }
        var command=new Command(); var chooser=new ClassicScanSurface {DataContext=new {IsNotScanning=true,StartQuickScanCommand=command,StartFullScanCommand=command,StartCustomScanCommand=command,StartSelectedCustomScanCommand=command,SelectCustomFolderCommand=command,SelectedCustomFolder="",OpenActiveScanWindowCommand=command,OpenSchedulerCommand=command,OpenReportsCommand=command,RefreshReportsCommand=command,ReportHistoryStatus="Önizleme — gerçek test sonucu değildir.",ReportHistory=new ObservableCollection<ScanReportRecord>()}};
        var body=new Border {Child=chooser,Padding=new Thickness(28)}; Grid.SetColumn(body,1);shell.Children.Add(body);Layout(host,1180);
        Assert.NotNull(selected);Assert.True(selected!.Focusable);Assert.True(selected.IsTabStop);
        Assert.Equal(Visibility.Visible,((Border)selected.Template.FindName("SelectionMark",selected)).Visibility);
        Assert.Equal(((SolidColorBrush)host.FindResource("BrushShellSidebarActive")).Color,((SolidColorBrush)((Border)selected.Template.FindName("ItemSurface",selected)).Background).Color);
        int clicked=0;selected.Click+=(_,_)=>clicked++;selected.InvokeNativeClick();Assert.Equal(1,clicked);Assert.Equal(0,command.Count);
        selected.IsActive=false;Assert.Equal(Visibility.Collapsed,((Border)selected.Template.FindName("SelectionMark",selected)).Visibility);selected.IsActive=true;
        Capture(host,$"shell-{theme}",1180);
    });

    private sealed class MenuProbe:Wpf.Ui.Controls.NavigationViewItem {public void InvokeNativeClick()=>OnClick();}

    /// <summary>Records five before/after inert native render workloads; these are not live scan or timer performance results.</summary>
    [Fact]
    public void RecordVectorRenderCostWithoutStartingTimers() => Sta(() =>
    {
        var measurements=new List<object>();
        for(int repeat=0;repeat<5;repeat++)
        {
            foreach(bool vector in new[] {false,true})
            {
                var route=vector?new ScanRouteVisual():null;
                var host=Host(route is null?new Border():route,"Dark",320);Layout(host,320);
                var bitmap=new RenderTargetBitmap(320,300,96,96,PixelFormats.Pbgra32);bitmap.Render(host);
                using var process=Process.GetCurrentProcess();process.Refresh();long beforeRam=process.WorkingSet64;
                var beforeCpu=process.TotalProcessorTime;long beforeAllocation=GC.GetAllocatedBytesForCurrentThread();var elapsed=Stopwatch.StartNew();
                for(int frame=0;frame<160;frame++)
                {
                    if(route!=null) {var translation=(TranslateTransform)route.FindName("CarTranslation");translation.X=ScanRouteMotionPolicy.Offset(frame/160d);translation.Y=0;((Canvas)route.FindName("FilePacket")).Opacity=Math.Pow(Math.Sin(frame/160d*Math.PI),2);}
                    bitmap.Clear();bitmap.Render(host);
                }
                elapsed.Stop();process.Refresh();
                measurements.Add(new {Repeat=repeat+1,Vector=vector,Frames=160,WallMs=elapsed.Elapsed.TotalMilliseconds,CpuMs=(process.TotalProcessorTime-beforeCpu).TotalMilliseconds,WorkingSetBefore=beforeRam,WorkingSetAfter=process.WorkingSet64,ThreadAllocatedBytes=GC.GetAllocatedBytesForCurrentThread()-beforeAllocation});
                if(route!=null)Assert.False(route.IsAnimating);
            }
        }
        string dir=Environment.GetEnvironmentVariable("ULTRON_REVIEW_ARTIFACT_ROOT") ?? Path.Combine(Root(),"artifacts/flat-route-scan-fix-2026-10-08/tests");Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir,"inert-render-measurements.json"),JsonSerializer.Serialize(measurements,new JsonSerializerOptions {WriteIndented=true}));
    });
    private static Border Host(UIElement child,string theme,int width)
    {
        var host=new Border {Child=child,Width=width,Padding=new Thickness(24)};
        foreach(var r in new[] {$"Colors.{theme}","Typography","Components","SharedStyles"})host.Resources.MergedDictionaries.Add(new ResourceDictionary {Source=new Uri($"/UltronDefender;component/Resources/Themes/{r}.xaml",UriKind.Relative)});
        host.SetResourceReference(Border.BackgroundProperty,"BrushAppBg"); return host;
    }
    private static void Layout(FrameworkElement host,int width) { for(int i=0;i<3;i++) {host.Measure(new Size(width,double.PositiveInfinity));host.Arrange(new Rect(0,0,width,Math.Ceiling(host.DesiredSize.Height)));host.UpdateLayout();Pump();} }
    private static IEnumerable<TextBlock> Texts(DependencyObject parent) {for(int i=0;i<VisualTreeHelper.GetChildrenCount(parent);i++){var c=VisualTreeHelper.GetChild(parent,i);if(c is TextBlock t)yield return t;foreach(var x in Texts(c))yield return x;}}
    private static void Capture(FrameworkElement host,string name,int width)
    {
        var bitmap=new RenderTargetBitmap(width,(int)Math.Ceiling(host.ActualHeight),96,96,PixelFormats.Pbgra32);bitmap.Render(host);
        var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));var dir=Path.Combine(AppContext.BaseDirectory,"ScanRoutePreview");Directory.CreateDirectory(dir);using var stream=File.Create(Path.Combine(dir,name+".png"));encoder.Save(stream);
    }
    private static void Pump() {var frame=new DispatcherFrame();Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle,new Action(()=>frame.Continue=false));Dispatcher.PushFrame(frame);}
    private static void Sta(Action action)
    {
        Exception? error=null;var thread=new Thread(()=>{try {action();}catch(Exception ex){error=ex;}finally{Dispatcher.CurrentDispatcher.InvokeShutdown();}}){IsBackground=true};thread.SetApartmentState(ApartmentState.STA);thread.Start();Assert.True(thread.Join(TimeSpan.FromSeconds(20)));if(error!=null)ExceptionDispatchInfo.Capture(error).Throw();
    }
    private sealed class Command:ICommand {public int Count{get;private set;}public event EventHandler? CanExecuteChanged{add{}remove{}}public bool CanExecute(object? p)=>true;public void Execute(object? p)=>Count++;}
}
