using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class ActiveScanWindow : Window
    {
        private static ActiveScanWindow? _activeInstance;
        private DispatcherTimer? _animTimer;
        private double _laserPos = 10;
        private double _laserDir = 2.5;

        public ScanViewModel ViewModel { get; }

        public ActiveScanWindow(ScanViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();

            Loaded += OnWindowLoaded;
            Closed += OnWindowClosed;
        }

        private void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            // Smooth, robust laser sweep animation using code-behind DispatcherTimer (Zero freeze issues)
            _animTimer = new DispatcherTimer(DispatcherPriority.Render)
            {
                Interval = TimeSpan.FromMilliseconds(25)
            };
            _animTimer.Tick += (s, ev) =>
            {
                if (LaserLine != null && LaserCanvas != null)
                {
                    _laserPos += _laserDir;
                    if (_laserPos > 140)
                    {
                        _laserPos = 140;
                        _laserDir = -2.5;
                    }
                    else if (_laserPos < 10)
                    {
                        _laserPos = 10;
                        _laserDir = 2.5;
                    }
                    Canvas.SetLeft(LaserLine, _laserPos);
                }
            };
            _animTimer.Start();
        }

        private void OnWindowClosed(object? sender, EventArgs e)
        {
            _animTimer?.Stop();
            if (_activeInstance == this) _activeInstance = null;
        }

        public static void ShowScanWindow(ScanViewModel viewModel)
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                try
                {
                    if (_activeInstance != null && _activeInstance.IsLoaded)
                    {
                        if (_activeInstance.WindowState == WindowState.Minimized)
                        {
                            _activeInstance.WindowState = WindowState.Normal;
                        }
                        _activeInstance.Show();
                        _activeInstance.Activate();
                        _activeInstance.Topmost = true;
                        _activeInstance.Topmost = false;
                        _activeInstance.Focus();
                        return;
                    }

                    var win = new ActiveScanWindow(viewModel);
                    _activeInstance = win;
                    win.Show();
                    win.Activate();
                    win.Topmost = true;
                    win.Topmost = false;
                    win.Focus();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine($"ActiveScanWindow Show error: {ex}");
                }
            });
        }

        private void OnCloseClicked(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}