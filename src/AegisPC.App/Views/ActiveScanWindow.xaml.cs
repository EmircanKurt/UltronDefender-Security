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
            ViewModel.PropertyChanged += OnViewModelPropertyChanged;
        }

        private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(ScanViewModel.IsPaused))
            {
                Dispatcher.InvokeAsync(() =>
                {
                    if (ViewModel.IsPaused)
                    {
                        _animTimer?.Stop();
                    }
                    else if (ViewModel.IsScanning)
                    {
                        _animTimer?.Start();
                    }
                });
            }
            else if (e.PropertyName == nameof(ScanViewModel.IsScanning))
            {
                Dispatcher.InvokeAsync(() =>
                {
                    if (ViewModel.IsScanning && !ViewModel.IsPaused) _animTimer?.Start();
                    else _animTimer?.Stop();
                });
            }
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
            if (ViewModel.IsScanning && !ViewModel.IsPaused)
            {
                _animTimer.Start();
            }
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            if (ViewModel.IsScanning)
            {
                var result = MessageBox.Show(
                    "Aktif bir virüs taraması devam ediyor.\n\nTaramayı tamamen iptal etmek mi istiyorsunuz?\n\n[Evet] Taramayı İptal Et\n[Hayır] Pencereyi Kapat (Tarama Arka Planda Devam Etsin)\n[İptal] Vazgeç",
                    "Ultron Defender - Tarama Durumu",
                    MessageBoxButton.YesNoCancel,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    ViewModel.CancelScan();
                }
                else if (result == MessageBoxResult.Cancel)
                {
                    e.Cancel = true;
                    return;
                }
            }

            base.OnClosing(e);
        }

        private void OnWindowClosed(object? sender, EventArgs e)
        {
            _animTimer?.Stop();
            ViewModel.PropertyChanged -= OnViewModelPropertyChanged;
            if (_activeInstance == this) _activeInstance = null;
        }

        public static ActiveScanWindow? ActiveInstance => _activeInstance;

        public static void ShowScanWindow(ScanViewModel viewModel)
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                try
                {
                    var mainWindow = Application.Current?.MainWindow;

                    if (_activeInstance != null)
                    {
                        try
                        {
                            if (_activeInstance.WindowState == WindowState.Minimized)
                            {
                                _activeInstance.WindowState = WindowState.Normal;
                            }
                            if (mainWindow != null && mainWindow.IsVisible && _activeInstance.Owner == null)
                            {
                                _activeInstance.Owner = mainWindow;
                            }
                            _activeInstance.Show();
                            _activeInstance.Activate();
                            _activeInstance.Focus();
                            return;
                        }
                        catch (Exception reactivateEx)
                        {
                            System.Diagnostics.Trace.WriteLine($"Existing ActiveScanWindow reactivate error: {reactivateEx}");
                            _activeInstance = null;
                        }
                    }

                    var win = new ActiveScanWindow(viewModel);
                    if (mainWindow != null && mainWindow.IsVisible)
                    {
                        win.Owner = mainWindow;
                    }
                    _activeInstance = win;
                    win.Show();
                    win.Activate();
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

        private void OnScanTabClicked(object sender, RoutedEventArgs e) => ShowScannerTab();
        private void OnReportsTabClicked(object sender, RoutedEventArgs e) => ShowReportsTab();
        private void OnSchedulerTabClicked(object sender, RoutedEventArgs e) => ShowSchedulerTab();

        private void ShowScannerTab()
        {
            ScannerPanel.Visibility = Visibility.Visible;
            ReportsPanel.Visibility = Visibility.Collapsed;
            SchedulerPanel.Visibility = Visibility.Collapsed;
        }

        private void ShowReportsTab()
        {
            ScannerPanel.Visibility = Visibility.Collapsed;
            SchedulerPanel.Visibility = Visibility.Collapsed;
            ReportsPanel.Visibility = Visibility.Visible;
            _ = ViewModel.RefreshReportsAsync();
        }

        private void ShowSchedulerTab()
        {
            var settings = App.ServiceProvider?.GetService(typeof(SettingsViewModel)) as SettingsViewModel;
            if (settings == null)
            {
                Serilog.Log.Warning("Shared settings view model is unavailable for the scan scheduler tab");
                MessageBox.Show(this, "Zamanlayıcı ayarları hazır değil. Ana uygulamanın Ayarlar sayfasını kullanın.", "Zamanlayıcı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            SchedulerPanel.DataContext = settings;
            ScannerPanel.Visibility = Visibility.Collapsed;
            ReportsPanel.Visibility = Visibility.Collapsed;
            SchedulerPanel.Visibility = Visibility.Visible;
        }

        /// <summary>Opens report history without starting a new scan or changing an existing scan's ownership.</summary>
        public static void ShowReportsWindow(ScanViewModel viewModel)
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                ShowScanWindow(viewModel);
                _activeInstance?.ShowReportsTab();
            });
        }

        /// <summary>Opens the scheduler controls backed by the shared settings view model, without directly changing service state.</summary>
        public static void ShowSchedulerWindow(ScanViewModel viewModel)
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                ShowScanWindow(viewModel);
                _activeInstance?.ShowSchedulerTab();
            });
        }
    }
}
