using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using AegisPC.App.Helpers;

namespace AegisPC.App.Controls;

/// <summary>Decorative, local vector route synchronized to scan activity; owns and releases its limited timer and window subscriptions.</summary>
public partial class ScanRouteVisual : UserControl
{
    /// <summary>Identifies observed scan-running state, not a simulated activity flag.</summary>
    public static readonly DependencyProperty IsRunningProperty = DependencyProperty.Register(nameof(IsRunning), typeof(bool), typeof(ScanRouteVisual), new PropertyMetadata(false, OnActivityChanged));
    /// <summary>Identifies pause state; pause stops the timer and retains the current pose.</summary>
    public static readonly DependencyProperty IsPausedProperty = DependencyProperty.Register(nameof(IsPaused), typeof(bool), typeof(ScanRouteVisual), new PropertyMetadata(false, OnStateChanged));
    /// <summary>Identifies observed file activity; a change renews the presentation's freshness budget.</summary>
    public static readonly DependencyProperty CurrentFileProperty = DependencyProperty.Register(nameof(CurrentFile), typeof(string), typeof(ScanRouteVisual), new PropertyMetadata(string.Empty, OnActivityChanged));
    /// <summary>Identifies observed counter activity, including files sharing a path; it is not an invented progress percentage.</summary>
    public static readonly DependencyProperty ActivityStampProperty = DependencyProperty.Register(nameof(ActivityStamp), typeof(string), typeof(ScanRouteVisual), new PropertyMetadata(string.Empty, OnActivityChanged));
    /// <summary>Identifies optional motion permission; Windows animation and rendering policy still take precedence.</summary>
    public static readonly DependencyProperty IsMotionEnabledProperty = DependencyProperty.Register(nameof(IsMotionEnabled), typeof(bool), typeof(ScanRouteVisual), new PropertyMetadata(true, OnStateChanged));
    private readonly DispatcherTimer _timer;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private Window? _owner;
    private bool _attached;
    private double _lastActivity, _lastFrame, _phase;
    /// <summary>Builds a static pose; construction never starts a scan, timer or static event subscription.</summary>
    public ScanRouteVisual()
    {
        InitializeComponent();
        _timer = new DispatcherTimer(DispatcherPriority.Background, Dispatcher) { Interval = ScanRouteMotionPolicy.UpdateInterval };
        _timer.Tick += OnTick;
        Loaded += OnLoaded; Unloaded += (_, _) => Detach(); IsVisibleChanged += (_, _) => Synchronize();
    }
    /// <summary>Gets or sets actual scan-running state.</summary>
    public bool IsRunning { get => (bool)GetValue(IsRunningProperty); set => SetValue(IsRunningProperty, value); }
    /// <summary>Gets or sets actual scan pause state.</summary>
    public bool IsPaused { get => (bool)GetValue(IsPausedProperty); set => SetValue(IsPausedProperty, value); }
    /// <summary>Gets or sets the current file activity identity for freshness only.</summary>
    public string CurrentFile { get => (string)GetValue(CurrentFileProperty); set => SetValue(CurrentFileProperty, value); }
    /// <summary>Gets or sets counter activity used to renew freshness.</summary>
    public string ActivityStamp { get => (string)GetValue(ActivityStampProperty); set => SetValue(ActivityStampProperty, value); }
    /// <summary>Gets or sets optional UI motion permission; disabling it stops immediately.</summary>
    public bool IsMotionEnabled { get => (bool)GetValue(IsMotionEnabledProperty); set => SetValue(IsMotionEnabledProperty, value); }
    /// <summary>Reports timer state for diagnostics; false does not mean that the engine has stopped.</summary>
    public bool IsAnimating => _timer.IsEnabled;
    private static void OnActivityChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
    {
        var route = (ScanRouteVisual)sender; route._lastActivity = route._clock.Elapsed.TotalSeconds;
        if (route._timer != null) route.Synchronize();
    }
    private static void OnStateChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
    { var route = (ScanRouteVisual)sender; if (route._timer != null) route.Synchronize(); }
    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (!_attached)
        {
            _owner = Window.GetWindow(this);
            if (_owner != null) { _owner.StateChanged += OnEnvironmentChanged; _owner.IsVisibleChanged += OnOwnerVisible; _owner.Closed += OnOwnerClosed; }
            SystemParameters.StaticPropertyChanged += OnSystemChanged; RenderCapability.TierChanged += OnEnvironmentChanged; _attached = true;
        }
        Synchronize();
    }
    private void Detach()
    {
        _timer.Stop();
        if (!_attached) return;
        if (_owner != null) { _owner.StateChanged -= OnEnvironmentChanged; _owner.IsVisibleChanged -= OnOwnerVisible; _owner.Closed -= OnOwnerClosed; }
        SystemParameters.StaticPropertyChanged -= OnSystemChanged; RenderCapability.TierChanged -= OnEnvironmentChanged;
        _owner = null; _attached = false;
    }
    private void OnEnvironmentChanged(object? sender, EventArgs e) => Synchronize();
    private void OnOwnerVisible(object sender, DependencyPropertyChangedEventArgs e) => Synchronize();
    private void OnOwnerClosed(object? sender, EventArgs e) => Detach();
    private void OnSystemChanged(object? sender, PropertyChangedEventArgs e) => Synchronize();
    private bool CanRun() => ScanRouteMotionPolicy.CanAnimate(IsRunning, IsPaused, IsLoaded, IsVisible,
        _owner?.IsVisible == true, _owner?.WindowState == WindowState.Minimized,
        IsMotionEnabled && UiMotionPolicy.CanAnimate, _clock.Elapsed.TotalSeconds - _lastActivity);
    private void Synchronize()
    {
        MotionLabel.Text = !IsRunning ? "Tarama bekleniyor" : IsPaused ? "Duraklatıldı"
            : _clock.Elapsed.TotalSeconds - _lastActivity >= ScanRouteMotionPolicy.ActivityAgeLimitSeconds ? "İlerleme bekleniyor" : "Dosya rotası";
        if (!CanRun()) { _timer.Stop(); return; }
        if (!_timer.IsEnabled) { _lastFrame = _clock.Elapsed.TotalSeconds; _timer.Start(); }
    }
    private void OnTick(object? sender, EventArgs e)
    {
        if (!CanRun()) { Synchronize(); return; }
        double now = _clock.Elapsed.TotalSeconds;
        _phase = ScanRouteMotionPolicy.Advance(_phase, now - _lastFrame); _lastFrame = now;
        CarTranslation.X = ScanRouteMotionPolicy.Offset(_phase);
        CarTranslation.Y = 0;
        FilePacket.Opacity = Math.Pow(Math.Sin(_phase * Math.PI), 2);
    }
}
