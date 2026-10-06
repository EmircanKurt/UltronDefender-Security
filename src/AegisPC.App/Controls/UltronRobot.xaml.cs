using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using AegisPC.App.Helpers;

namespace AegisPC.App.Controls;

/// <summary>
/// Presents the accessible Ultron robot action with bounded local-window pointer motion.
/// Timers run only while the pose is changing; all input and static subscriptions are removed on unload.
/// </summary>
public partial class UltronRobot : UserControl
{
    /// <summary>Identifies the command invoked by the standard keyboard-accessible robot button.</summary>
    public static readonly DependencyProperty CommandProperty = DependencyProperty.Register(
        nameof(Command), typeof(ICommand), typeof(UltronRobot));

    /// <summary>Identifies whether optional motion may be used; Windows and rendering policy still take precedence.</summary>
    public static readonly DependencyProperty IsMotionEnabledProperty = DependencyProperty.Register(
        nameof(IsMotionEnabled), typeof(bool), typeof(UltronRobot), new PropertyMetadata(true, OnInteractionChanged));

    /// <summary>Identifies whether the robot is an action or a static decorative presentation.</summary>
    public static readonly DependencyProperty IsInteractiveProperty = DependencyProperty.Register(
        nameof(IsInteractive), typeof(bool), typeof(UltronRobot), new PropertyMetadata(true, OnInteractionChanged));

    private readonly DispatcherTimer _motionTimer;
    private Window? _owner;
    private bool _isAttached;
    private bool _isTrackingPointer;
    private Point _targetGaze;
    private double _targetLift;
    private double _targetScale = 1;

    /// <summary>Initializes the vector control without starting a timer or installing input subscriptions.</summary>
    public UltronRobot()
    {
        InitializeComponent();
        _motionTimer = new DispatcherTimer(DispatcherPriority.Render, Dispatcher)
        {
            Interval = RobotMotionPolicy.UpdateInterval
        };
        _motionTimer.Tick += OnMotionTick;
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        IsVisibleChanged += OnControlVisibilityChanged;
    }

    /// <summary>Gets or sets the action executed by click, Enter, Space, or the button's automation peer.</summary>
    public ICommand? Command
    {
        get => (ICommand?)GetValue(CommandProperty);
        set => SetValue(CommandProperty, value);
    }

    /// <summary>Gets or sets permission for local motion; disabled motion immediately restores the neutral pose.</summary>
    public bool IsMotionEnabled
    {
        get => (bool)GetValue(IsMotionEnabledProperty);
        set => SetValue(IsMotionEnabledProperty, value);
    }

    /// <summary>Gets or sets whether the robot participates in input, keyboard focus, and command interaction.</summary>
    public bool IsInteractive
    {
        get => (bool)GetValue(IsInteractiveProperty);
        set => SetValue(IsInteractiveProperty, value);
    }

    private static void OnInteractionChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
    {
        if (sender is not UltronRobot robot || robot.RobotButton == null) return;
        robot.RobotButton.Focusable = robot.IsInteractive;
        robot.RobotButton.IsTabStop = robot.IsInteractive;
        robot.RobotButton.IsHitTestVisible = robot.IsInteractive;
        robot.RobotButton.IsEnabled = robot.IsInteractive;
        if (!robot.IsInteractive || !robot.IsMotionEnabled)
        {
            robot.Detach();
            return;
        }
        if (robot.IsLoaded) robot.AttachToOwner();
        robot.SynchronizeTracking();
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        AttachToOwner();
        SynchronizeTracking();
    }

    private void AttachToOwner()
    {
        if (_isAttached || !IsInteractive || !IsMotionEnabled) return;
        _owner = Window.GetWindow(this);
        if (_owner == null) return;
        _isAttached = true;
        _owner.Activated += OnWindowEnvironmentChanged;
        _owner.Deactivated += OnWindowEnvironmentChanged;
        _owner.StateChanged += OnWindowEnvironmentChanged;
        _owner.Closed += OnOwnerClosed;
        _owner.IsVisibleChanged += OnWindowVisibilityChanged;
        SystemParameters.StaticPropertyChanged += OnSystemParameterChanged;
        RenderCapability.TierChanged += OnWindowEnvironmentChanged;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e) => Detach();

    private void OnOwnerClosed(object? sender, EventArgs e) => Detach();

    private void Detach()
    {
        StopPointerTracking();
        if (_owner != null && _isAttached)
        {
            _owner.Activated -= OnWindowEnvironmentChanged;
            _owner.Deactivated -= OnWindowEnvironmentChanged;
            _owner.StateChanged -= OnWindowEnvironmentChanged;
            _owner.Closed -= OnOwnerClosed;
            _owner.IsVisibleChanged -= OnWindowVisibilityChanged;
            SystemParameters.StaticPropertyChanged -= OnSystemParameterChanged;
            RenderCapability.TierChanged -= OnWindowEnvironmentChanged;
        }
        _isAttached = false;
        _owner = null;
    }

    private void OnWindowEnvironmentChanged(object? sender, EventArgs e) => SynchronizeTracking();

    private void OnWindowVisibilityChanged(object sender, DependencyPropertyChangedEventArgs e) => SynchronizeTracking();

    private void OnControlVisibilityChanged(object sender, DependencyPropertyChangedEventArgs e) => SynchronizeTracking();

    private void OnSystemParameterChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(SystemParameters.ClientAreaAnimation))
            Dispatcher.InvokeAsync(SynchronizeTracking);
    }

    private bool CanTrackPointer() => _owner != null && RobotMotionPolicy.CanTrackPointer(
        IsLoaded, IsVisible, _owner.IsVisible, _owner.IsActive,
        _owner.WindowState == WindowState.Minimized, IsInteractive && IsMotionEnabled && UiMotionPolicy.CanAnimate);

    private void SynchronizeTracking()
    {
        if (!CanTrackPointer())
        {
            StopPointerTracking();
            return;
        }
        if (_isTrackingPointer || _owner == null) return;
        _owner.PreviewMouseMove += OnPointerMoved;
        _owner.MouseLeave += OnPointerLeftWindow;
        _isTrackingPointer = true;
    }

    private void StopPointerTracking()
    {
        if (_owner != null && _isTrackingPointer)
        {
            _owner.PreviewMouseMove -= OnPointerMoved;
            _owner.MouseLeave -= OnPointerLeftWindow;
        }
        _isTrackingPointer = false;
        _motionTimer.Stop();
        _targetGaze = new Point();
        _targetLift = 0;
        _targetScale = 1;
        GazeTransform.X = GazeTransform.Y = RobotLift.Y = 0;
        RobotScale.ScaleX = RobotScale.ScaleY = 1;
    }

    private void OnPointerMoved(object sender, MouseEventArgs e)
    {
        if (!CanTrackPointer())
        {
            SynchronizeTracking();
            return;
        }
        _targetGaze = RobotMotionPolicy.CalculateGaze(e.GetPosition(this), new Point(ActualWidth / 2, ActualHeight / 2));
        _targetLift = IsMouseOver ? -3 : 0;
        _targetScale = IsMouseOver ? 1.04 : 1;
        StartMotionIfNeeded();
    }

    private void OnPointerLeftWindow(object sender, MouseEventArgs e)
    {
        _targetGaze = new Point();
        _targetLift = 0;
        _targetScale = 1;
        StartMotionIfNeeded();
    }

    private bool HasPendingMotion() => GazeTransform.X != _targetGaze.X || GazeTransform.Y != _targetGaze.Y ||
        RobotLift.Y != _targetLift || RobotScale.ScaleX != _targetScale;

    private void StartMotionIfNeeded()
    {
        if (CanTrackPointer() && HasPendingMotion() && !_motionTimer.IsEnabled) _motionTimer.Start();
    }

    private void OnMotionTick(object? sender, EventArgs e)
    {
        if (!CanTrackPointer())
        {
            SynchronizeTracking();
            return;
        }
        GazeTransform.X = RobotMotionPolicy.Approach(GazeTransform.X, _targetGaze.X);
        GazeTransform.Y = RobotMotionPolicy.Approach(GazeTransform.Y, _targetGaze.Y);
        RobotLift.Y = RobotMotionPolicy.Approach(RobotLift.Y, _targetLift);
        RobotScale.ScaleX = RobotScale.ScaleY = RobotMotionPolicy.Approach(RobotScale.ScaleX, _targetScale);
        if (!HasPendingMotion()) _motionTimer.Stop();
    }
}
