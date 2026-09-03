using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AegisPC.Tests
{
    public class XamlStaticResourceIntegrityTests
    {
        [Fact]
        public void AllStaticResourceReferences_MustExistInThemeDictionaries()
        {
            // Find src/AegisPC.App folder
            var currentDir = AppDomain.CurrentDomain.BaseDirectory;
            var appDir = Path.GetFullPath(Path.Combine(currentDir, @"..\..\..\..\..\src\AegisPC.App"));
            if (!Directory.Exists(appDir))
            {
                // Fallback for different build structures
                appDir = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\src\AegisPC.App"));
            }

            Assert.True(Directory.Exists(appDir), $"AegisPC.App directory not found at: {appDir}");

            var xamlFiles = Directory.GetFiles(appDir, "*.xaml", SearchOption.AllDirectories);
            Assert.NotEmpty(xamlFiles);

            // 1. Collect all defined x:Key="..." attributes
            var definedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var file in xamlFiles)
            {
                var content = File.ReadAllText(file);
                var matches = Regex.Matches(content, @"x:Key=""([^""]+)""");
                foreach (Match m in matches)
                {
                    definedKeys.Add(m.Groups[1].Value);
                }
            }

            Assert.True(definedKeys.Count > 100, $"Expected >100 defined keys, but found {definedKeys.Count}");

            // 2. Scan every XAML file for {StaticResource Key}
            var missingStaticList = new List<string>();
            foreach (var file in xamlFiles)
            {
                var lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    var matches = Regex.Matches(line, @"\{StaticResource\s+([^}]+)\}");
                    foreach (Match m in matches)
                    {
                        var key = m.Groups[1].Value.Trim();
                        // Filter out system or namespace-qualified keys
                        if (key.StartsWith("x:") || key.StartsWith("system:") || key.Contains(":"))
                        {
                            continue;
                        }

                        if (!definedKeys.Contains(key))
                        {
                            missingStaticList.Add($"{Path.GetFileName(file)}:L{i + 1} Missing StaticResource: '{key}'");
                        }
                    }
                }
            }

            Assert.True(missingStaticList.Count == 0, 
                $"Found {missingStaticList.Count} undefined StaticResource references:\n" + string.Join("\n", missingStaticList));
        }

        [Fact]
        public void Views_WhenInstantiatedInSTAThread_MustNotThrowXamlParseException()
        {
            Exception? threadException = null;
            var thread = new Thread(() =>
            {
                try
                {
                    // Ensure WPF Application object exists
                    if (System.Windows.Application.Current == null)
                    {
                        new System.Windows.Application();
                    }

                    // Load App Theme Dictionaries if not already present
                    var app = System.Windows.Application.Current;
                    Assert.NotNull(app);
                    if (app.Resources.MergedDictionaries.Count == 0)
                    {
                        var dicts = new[]
                        {
                            "pack://application:,,,/UltronDefender;component/Resources/Themes/Typography.xaml",
                            "pack://application:,,,/UltronDefender;component/Resources/Themes/Colors.Dark.xaml",
                            "pack://application:,,,/UltronDefender;component/Resources/Themes/Components.xaml",
                            "pack://application:,,,/UltronDefender;component/Resources/Themes/SharedStyles.xaml"
                        };

                        foreach (var uriStr in dicts)
                        {
                            try
                            {
                                var dict = new ResourceDictionary { Source = new Uri(uriStr, UriKind.Absolute) };
                                app.Resources.MergedDictionaries.Add(dict);
                            }
                            catch
                            {
                                // Component pack URIs might require standalone pack registration in unit test runners
                            }
                        }
                    }

                    // Build ServiceProvider to instantiate all Views
                    var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
                    AegisPC.App.Startup.ServiceRegistration.RegisterServices(services);
                    var sp = services.BuildServiceProvider();

                    var viewTypes = new[]
                    {
                        typeof(AegisPC.App.Views.PerformanceView),
                        typeof(AegisPC.App.Views.DashboardView),
                        typeof(AegisPC.App.Views.ApplicationsView),
                        typeof(AegisPC.App.Views.BrowserSecurityView),
                        typeof(AegisPC.App.Views.CrashAnalysisView),
                        typeof(AegisPC.App.Views.HistoryView),
                        typeof(AegisPC.App.Views.IncidentCenterView),
                        typeof(AegisPC.App.Views.NetworkProtectionView),
                        typeof(AegisPC.App.Views.ParentalControlsView),
                        typeof(AegisPC.App.Views.ProcessListView),
                        typeof(AegisPC.App.Views.QuarantineView),
                        typeof(AegisPC.App.Views.RansomwareShieldView),
                        typeof(AegisPC.App.Views.RansomwareSettingsWindow),
                        typeof(AegisPC.App.Views.RecommendationsView),
                        typeof(AegisPC.App.Views.ScanView),
                        typeof(AegisPC.App.Views.SecurityView),
                        typeof(AegisPC.App.Views.SettingsView),
                        typeof(AegisPC.App.Views.StartupManagerView),
                        typeof(AegisPC.App.Views.WindowsEventsView)
                    };

                    foreach (var vt in viewTypes)
                    {
                        try
                        {
                            var view = sp.GetService(vt) as UIElement;
                            Assert.NotNull(view);
                            view.Measure(new System.Windows.Size(1920, 1080));
                            view.Arrange(new System.Windows.Rect(0, 0, 1920, 1080));
                            view.UpdateLayout();
                        }
                        catch (System.Windows.Markup.XamlParseException xpe)
                        {
                            throw new InvalidOperationException($"View {vt.Name} failed XAML parse: {xpe.Message} (Inner: {xpe.InnerException?.Message})", xpe);
                        }
                    }
                }
                catch (Exception ex)
                {
                    threadException = ex;
                }
            });

            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join(10000);

            if (threadException != null)
            {
                throw threadException;
            }
        }
    }
}
