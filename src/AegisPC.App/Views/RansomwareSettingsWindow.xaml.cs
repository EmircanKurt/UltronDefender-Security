using System;
using System.Windows;
using AegisPC.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace AegisPC.App.Views
{
    /// <summary>
    /// Fidye Kalkanı gelişmiş ayarlarını (korumalı klasörler, izinli uygulamalar, canary durumu)
    /// modal pencerede yöneten pencere sınıfı.
    /// </summary>
    public partial class RansomwareSettingsWindow : Window
    {
        private static RansomwareSettingsWindow? _activeInstance;

        public RansomwareSettingsWindow()
        {
            InitializeComponent();

            try
            {
                Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri("pack://application:,,,/AegisPC.App;component/Resources/Images/app.ico", UriKind.RelativeOrAbsolute));
            }
            catch { }

            var view = App.ServiceProvider?.GetService<RansomwareShieldView>() ?? new RansomwareShieldView();
            ContentFrame.Content = view;
        }

        /// <summary>
        /// Tekil pencere örneğini açar veya var olanı öne getirir.
        /// </summary>
        public static void ShowOrActivate()
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
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
                        _activeInstance.Focus();
                        return;
                    }

                    var win = new RansomwareSettingsWindow();
                    var mainWin = Application.Current?.MainWindow;
                    if (mainWin != null && mainWin.IsVisible)
                    {
                        win.Owner = mainWin;
                    }
                    _activeInstance = win;
                    win.Closed += (s, e) => _activeInstance = null;
                    win.Show();
                    win.Activate();
                    win.Focus();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine($"RansomwareSettingsWindow ShowOrActivate error: {ex}");
                }
            });
        }

        private void OnCloseClicked(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
