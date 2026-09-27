using System;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using AegisPC.App.ViewModels;
using AegisPC.App.Views;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Security.Scanning;
using Xunit;
using WpfButton = System.Windows.Controls.Button;
using WpfSize = System.Windows.Size;

namespace AegisPC.Tests
{
    public class ActiveScanWindowButtonTests
    {
        [Fact]
        public void ActiveScanWindow_ButtonsArePresentAndBound()
        {
            Exception? threadEx = null;
            var thread = new Thread(() =>
            {
                try
                {
                    if (System.Windows.Application.Current == null)
                    {
                        new System.Windows.Application();
                    }

                    var app = System.Windows.Application.Current ?? throw new InvalidOperationException("WPF application was not initialized.");
                    if (app.Resources.MergedDictionaries.Count == 0)
                    {
                        var dicts = new[]
                        {
                            "pack://application:,,,/UltronDefender;component/Resources/Themes/Typography.xaml",
                            "pack://application:,,,/UltronDefender;component/Resources/Themes/Colors.Light.xaml",
                            "pack://application:,,,/UltronDefender;component/Resources/Themes/Components.xaml",
                            "pack://application:,,,/UltronDefender;component/Resources/Themes/SharedStyles.xaml"
                        };

                        foreach (var uriStr in dicts)
                        {
                            app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri(uriStr, UriKind.Absolute) });
                        }
                    }

                    var hashService = new HashService();
                    var sigVerifier = new SignatureVerifier();
                    var allowlist = new AllowlistService(hashService);
                    var findingService = new SecurityFindingService();
                    var scanner = new FileScannerService(hashService, sigVerifier, new RiskScoringEngine(), allowlist, findingService);
                    var coordinator = new ScanCoordinatorService(scanner, findingService);

                    var vm = new ScanViewModel(coordinator, findingService);
                    vm.ResetScanState(ScanType.Quick);

                    var win = new ActiveScanWindow(vm);
                    win.ApplyTemplate();
                    if (win.Content is FrameworkElement fe)
                    {
                        fe.ApplyTemplate();
                    }
                    win.Measure(new WpfSize(880, 580));
                    win.Arrange(new Rect(0, 0, 880, 580));
                    win.UpdateLayout();

                    // Find all buttons in ActiveScanWindow
                    var buttons = FindVisualChildren<WpfButton>(win);
                    WpfButton? pauseBtn = null;
                    WpfButton? cancelBtn = null;

                    var foundDescriptions = new System.Collections.Generic.List<string>();
                    foreach (var btn in buttons)
                    {
                        var contentStr = btn.Content?.ToString() ?? "(null content)";
                        foundDescriptions.Add($"'{contentStr}' (Cmd: {btn.Command?.GetType().Name ?? "null"})");
                        if (contentStr == "Duraklat" || contentStr == "Devam Et")
                        {
                            pauseBtn = btn;
                        }
                        else if (contentStr == "İptal")
                        {
                            cancelBtn = btn;
                        }
                    }

                    if (pauseBtn == null || cancelBtn == null)
                    {
                        throw new Exception("Buttons found: " + string.Join(", ", foundDescriptions));
                    }

                    Assert.NotNull(pauseBtn.Command);
                    Assert.NotNull(cancelBtn.Command);

                    Assert.True(pauseBtn.IsEnabled);
                    Assert.True(cancelBtn.IsEnabled);

                    // Execute pause
                    pauseBtn.Command.Execute(null);
                    Assert.True(vm.IsPaused);
                    Assert.Equal("Devam Et", vm.PauseButtonText);

                    // Execute cancel
                    cancelBtn.Command.Execute(null);
                    Assert.True(vm.IsCancellationRequested);
                    Assert.False(vm.IsScanning);
                    Assert.True(vm.IsScanFinishedView);
                }
                catch (Exception ex)
                {
                    threadEx = ex;
                }
            });

            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join(10000);

            if (threadEx != null)
            {
                throw threadEx;
            }
        }

        private static System.Collections.Generic.List<T> FindVisualChildren<T>(DependencyObject depObj) where T : DependencyObject
        {
            var list = new System.Collections.Generic.List<T>();
            if (depObj == null) return list;

            if (depObj is Visual or System.Windows.Media.Media3D.Visual3D)
            {
                for (int i = 0; i < VisualTreeHelper.GetChildrenCount(depObj); i++)
                {
                    var child = VisualTreeHelper.GetChild(depObj, i);
                    if (child is T t)
                    {
                        list.Add(t);
                    }
                    list.AddRange(FindVisualChildren<T>(child));
                }
            }

            foreach (var child in LogicalTreeHelper.GetChildren(depObj))
            {
                if (child is DependencyObject dChild)
                {
                    if (dChild is T target && !list.Contains(target))
                    {
                        list.Add(target);
                    }
                    list.AddRange(FindVisualChildren<T>(dChild));
                }
            }

            return list;
        }
    }
}
