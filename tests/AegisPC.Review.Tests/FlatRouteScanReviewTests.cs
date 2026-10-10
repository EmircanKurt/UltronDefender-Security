using System.IO;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using AegisPC.App.Controls;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

[CollectionDefinition("FlatRouteIsolated", DisableParallelization = true)]
/// <summary>Serializes temporary presentation flags against other test collections.</summary>
public sealed class FlatRouteIsolatedCollection { }

/// <summary>Finite viewport and fake-coordinator regressions; never starts an AV application or protection action.</summary>
[Collection("FlatRouteIsolated")]
public sealed class FlatRouteScanReviewTests
{
    /// <summary>Measures real control bounds at finite heights; only the body may scroll on smaller windows.</summary>
    [Theory]
    [InlineData("Dark", 932, 490)] [InlineData("Light", 932, 490)]
    [InlineData("Dark", 752, 350)] [InlineData("Light", 752, 350)]
    [InlineData("Dark", 420, 400)] [InlineData("Light", 420, 400)]
    public void FiniteHeight_KeepsProgressAndControlsVisible(string theme, int width, int height) => Sta(() =>
    {
        var view = new ActiveScanSurface { DataContext = new
        {
            IsScanning = true, IsPaused = false, CanControlScan = true, CurrentFile = @"C:\BenignFixture\long-file-name.dll",
            ScannedItemsFormatted = "63", ScanStatusText = "Başlangıç dosya taraması", ScanDurationFormatted = "0 dk 08 sn",
            ScannedBreakdownFormatted = "0 önbellekten • 0 imzalı geçti • 63 yeni tarandı", FailedCount = 14, TimedOutCount = 5,
            DetectionsCount = 0, FindingBreakdownText = "0 doğrulanmış • 0 inceleme gereken", PauseButtonText = "Duraklat",
            ActiveResourceProfileText = "Sistem Gereksinimleri • Auto • 3 işçi • RAM üst bütçesi 2.048 MiB • CPU hedefi ~%60 • Etkin 3/3 • Bekleyen 54",
            CpuAndRamFormatted = "CPU: %2,7 • RAM: 333 MB", ProgressPercentage = 42, RemainingEtaFormatted = "Hesaplanıyor..."
        }};
        var host = new Border { Child = view, Width = width, Height = height, Padding = new Thickness(8) };
        foreach (string resource in new[] { $"Colors.{theme}", "Typography", "Components", "SharedStyles" })
            host.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri($"/UltronDefender;component/Resources/Themes/{resource}.xaml", UriKind.Relative) });
        host.SetResourceReference(Border.BackgroundProperty, "BrushCardBg");
        for (int repeat = 0; repeat < 3; repeat++)
        { host.Measure(new Size(width, height)); host.Arrange(new Rect(0, 0, width, height)); host.UpdateLayout(); }
        foreach (string name in new[] { "PauseButton", "CancelButton", "ScanProgress" })
        {
            var element = (FrameworkElement)view.FindName(name);
            var bounds = element.TransformToAncestor(host).TransformBounds(new Rect(0, 0, element.ActualWidth, element.ActualHeight));
            Assert.InRange(bounds.Top, 0, height); Assert.InRange(bounds.Bottom, 0, height);
            Assert.InRange(bounds.Left, 0, width); Assert.InRange(bounds.Right, 0, width);
        }
        if (width == 932) Assert.InRange(((ScrollViewer)view.FindName("ScanScroll")).ScrollableHeight, 0, 1);
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32); bitmap.Render(host);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        string folder = Path.Combine(AppContext.BaseDirectory, "FlatRoutePreview"); Directory.CreateDirectory(folder);
        using var stream = File.Create(Path.Combine(folder, $"finite-{theme}-{width}-{height}.png")); encoder.Save(stream);
        Assert.False(((ScanRouteVisual)view.FindName("RouteVisual")).IsAnimating);
    });

    /// <summary>Fake cancellation does not become a terminal result until the coordinator reports actual completion.</summary>
    [Fact]
    public void Cancellation_RemainsPendingUntilActualTerminalEvent() => Sta(() =>
    {
        var coordinator = new Coordinator(); var vm = new ScanViewModel(scanCoordinator: coordinator);
        vm.ResetScanState(); vm.CurrentFile = "benign.dat"; vm.CancelScan();
        Assert.True(vm.IsScanning); Assert.False(vm.IsScanFinishedView); Assert.False(vm.CanControlScan);
        Assert.Equal("benign.dat", vm.CurrentFile); Assert.Contains("bekleniyor", vm.RemainingEtaFormatted);
        vm.CancelScan(); vm.TogglePauseResume(); Assert.Equal(1, coordinator.CancelCalls); Assert.Equal(0, coordinator.PauseCalls);
        coordinator.Finish(); Assert.False(vm.IsScanning); Assert.True(vm.IsScanFinishedView); Assert.False(vm.CanControlScan);
        vm.ResetScanState(); Assert.True(vm.CanControlScan);
        coordinator.Finish();
    });

    /// <summary>Reopening retains pause/pending cancellation and a genuinely new session clears stale pending state.</summary>
    [Fact]
    public void ReopenSync_PreservesActualPauseAndCancellation() => Sta(() =>
    {
        bool before = AegisPC.App.App.IsStartMinimized;
        try
        {
            AegisPC.App.App.IsStartMinimized = true;
            var coordinator = new Coordinator(); var vm = new ScanViewModel(scanCoordinator: coordinator);
            coordinator.IsScanning = true; coordinator.IsPaused = true; vm.SyncWithScanCoordinator();
            Assert.True(vm.IsPaused); Assert.Equal("Devam Et", vm.PauseButtonText);
            coordinator.State = ScanState.Cancelling; coordinator.IsPaused = false; vm.SyncWithScanCoordinator();
            Assert.True(vm.IsScanning); Assert.False(vm.CanControlScan); Assert.Contains("İptal", vm.ScanStatusText);
            coordinator.Finish();
            coordinator.State = ScanState.Scanning; coordinator.IsScanning = true; vm.SyncWithScanCoordinator();
            Assert.True(vm.CanControlScan); Assert.False(vm.IsScanFinishedView);
            coordinator.Finish();
        }
        finally { AegisPC.App.App.IsStartMinimized = before; }
    });

    /// <summary>Bounded metadata scheduling preserves candidates, source disposal and cancellation without trusting extensions.</summary>
    [Fact]
    public void BoundedScheduling_DrainsEveryWindow_AndRetainsUnknownFiles()
    {
        string directory = Path.Combine(Path.GetTempPath(), "UltronScheduling_" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try
        {
            var large = new FileInfo(Path.Combine(directory, "large.txt")); File.WriteAllBytes(large.FullName, new byte[8192]);
            var small = new FileInfo(Path.Combine(directory, "small.exe")); File.WriteAllText(small.FullName, "inert");
            var absent = new FileInfo(Path.Combine(directory, "unavailable.dll"));
            var next = new FileInfo(Path.Combine(directory, "next.bin")); File.WriteAllBytes(next.FullName, [1]);
            var all = StartupCandidateScheduling.Order([large, small, absent, next], default, 3).ToArray();
            Assert.Equal(new[] { small.FullName, large.FullName, absent.FullName, next.FullName }, all.Select(f => f.FullName));
            int reads = 0; bool disposed = false;
            IEnumerable<FileInfo> Source() { try { for (int i = 0; i < 1000; i++) { reads++; yield return large; } } finally { disposed = true; } }
            using var token = new CancellationTokenSource();
            using (var pending = StartupCandidateScheduling.Order(Source(), token.Token).GetEnumerator())
            { Assert.True(pending.MoveNext()); Assert.Equal(64, reads); token.Cancel(); Assert.Throws<OperationCanceledException>(() => pending.MoveNext()); }
            Assert.True(disposed);
        }
        finally { Directory.Delete(directory, true); }
    }

    private static void Sta(Action action)
    {
        Exception? error = null; var thread = new Thread(() => { try { action(); } catch (Exception ex) { error = ex; } finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); } }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); Assert.True(thread.Join(TimeSpan.FromSeconds(20)));
        if (error != null) ExceptionDispatchInfo.Capture(error).Throw();
    }

    private sealed class Coordinator : IScanCoordinatorService
    {
        public bool IsScanning { get; set; } public bool IsPaused { get; set; } public ScanState State { get; set; }
        public ScanStopReason StopReason => default; public ScanType CurrentScanType => ScanType.Quick;
        public double ProgressPercent => 0; public string CurrentFile => "benign.dat"; public int ScannedFiles => 0;
        public int TotalFiles => 1; public int FindingsCount => 0; public string StatusText => "Duraklatıldı";
        public IReadOnlyList<SecurityFinding> CurrentFindings => []; public TimeSpan ElapsedTime => TimeSpan.Zero;
        public IScanSession? CurrentSession => null; public int CancelCalls; public int PauseCalls;
        public event Action<IScanSession>? ScanSessionStarted { add { } remove { } }
        public event Action<ScanProgress>? ProgressChanged { add { } remove { } }
        public event Action<ScanResult>? ScanCompleted;
        public Task<ScanResult?> StartScanAsync(ScanType type, string path = "") => throw new NotSupportedException();
        public IDisposable RegisterExternalScanner(Action pause, Action resume, Action cancel) => throw new NotSupportedException();
        public void RegisterExternalScanProgress(ScanProgress progress) => throw new NotSupportedException();
        public void CompleteExternalScan(ScanResult result) => throw new NotSupportedException();
        public void PauseScan() { PauseCalls++; IsPaused = true; } public void ResumeScan() => IsPaused = false;
        public void CancelScan() { CancelCalls++; State = ScanState.Cancelling; }
        public void Finish() { IsScanning = false; State = ScanState.Cancelled; ScanCompleted?.Invoke(new ScanResult { Status = ScanStatus.Cancelled }); }
    }
}
