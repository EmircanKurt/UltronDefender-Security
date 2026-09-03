using System;
using System.IO;
using AegisPC.Core.Enums;
using Xunit;

namespace AegisPC.Tests
{
    public class ThemeAndScrollIntegrationTests
    {
        private static string GetAppDir()
        {
            var currentDir = AppDomain.CurrentDomain.BaseDirectory;
            var appDir = Path.GetFullPath(Path.Combine(currentDir, @"..\..\..\..\..\src\AegisPC.App"));
            if (!Directory.Exists(appDir))
            {
                appDir = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\src\AegisPC.App"));
            }
            if (!Directory.Exists(appDir))
            {
                // Traverse up until we find src/AegisPC.App
                var dir = new DirectoryInfo(currentDir);
                while (dir != null && !Directory.Exists(Path.Combine(dir.FullName, "src", "AegisPC.App")))
                {
                    dir = dir.Parent;
                }
                if (dir != null)
                {
                    appDir = Path.Combine(dir.FullName, "src", "AegisPC.App");
                }
            }
            return appDir;
        }

        [Fact]
        public void ColorsDarkXaml_ContainsRequiredThemeTokens()
        {
            var appDir = GetAppDir();
            var darkThemePath = Path.Combine(appDir, "Resources", "Themes", "Colors.Dark.xaml");
            Assert.True(File.Exists(darkThemePath), $"Colors.Dark.xaml should exist at {darkThemePath}");

            string content = File.ReadAllText(darkThemePath);

            // Assert authoritative dark theme tokens exist
            Assert.Contains("ColorAppBg", content);
            Assert.Contains("#0F141C", content); // Obsidian App Canvas
            Assert.Contains("ColorSidebarBg", content);
            Assert.Contains("#0A0D14", content); // Charcoal Sidebar
            Assert.Contains("ColorCardBg", content);
            Assert.Contains("#161D27", content); // Elevated Card Surface
            Assert.Contains("NavigationViewPaneBackground", content);
            Assert.Contains("NavigationViewDefaultPaneBackground", content);
            Assert.Contains("NavigationViewExpandedPaneBackground", content);
        }

        [Fact]
        public void ColorsLightXaml_ContainsRequiredThemeTokens()
        {
            var appDir = GetAppDir();
            var lightThemePath = Path.Combine(appDir, "Resources", "Themes", "Colors.Light.xaml");
            Assert.True(File.Exists(lightThemePath), $"Colors.Light.xaml should exist at {lightThemePath}");

            string content = File.ReadAllText(lightThemePath);

            Assert.Contains("ColorAppBg", content);
            Assert.Contains("ColorSidebarBg", content);
            Assert.Contains("ColorCardBg", content);
        }

        [Fact]
        public void MainWindow_TitleBarAndSidebarLogo_AreEnlarged()
        {
            var appDir = GetAppDir();
            var mainWindowPath = Path.Combine(appDir, "MainWindow.xaml");
            Assert.True(File.Exists(mainWindowPath), $"MainWindow.xaml should exist at {mainWindowPath}");

            string content = File.ReadAllText(mainWindowPath);

            // TitleBar icon must use ultron_logo.png at 26x26
            Assert.Contains("ultron_logo.png", content);
            Assert.Contains("Width=\"26\" Height=\"26\"", content);

            // Sidebar PaneHeader must be enlarged to 62x62 with 26pt ULTRON text
            Assert.Contains("Width=\"62\" Height=\"62\"", content);
            Assert.Contains("FontSize=\"26\" FontWeight=\"Black\"", content);
        }

        [Fact]
        public void SettingsView_ContainsThemeSelectionCard()
        {
            var appDir = GetAppDir();
            var settingsViewPath = Path.Combine(appDir, "Views", "SettingsView.xaml");
            Assert.True(File.Exists(settingsViewPath), $"SettingsView.xaml should exist at {settingsViewPath}");

            string content = File.ReadAllText(settingsViewPath);

            // Must contain theme selection cards for Light, Dark, System
            Assert.Contains("Görünüm ve Tema Tercihi", content);
            Assert.Contains("IsLightThemeSelected", content);
            Assert.Contains("IsDarkThemeSelected", content);
            Assert.Contains("IsSystemThemeSelected", content);
            Assert.Contains("SetLightThemeCommand", content);
            Assert.Contains("SetDarkThemeCommand", content);
            Assert.Contains("SetSystemThemeCommand", content);
        }

        [Fact]
        public void Typography_DataMonospaceTextBoxStyle_HasBubbleScroll()
        {
            var appDir = GetAppDir();
            var typographyPath = Path.Combine(appDir, "Resources", "Themes", "Typography.xaml");
            Assert.True(File.Exists(typographyPath), $"Typography.xaml should exist at {typographyPath}");

            string content = File.ReadAllText(typographyPath);

            Assert.Contains("helpers:MouseWheelScrollHelper.BubbleScroll", content);
        }

        [Fact]
        public void ProcessListView_HasSmoothScrollingConfigured()
        {
            var appDir = GetAppDir();
            var path = Path.Combine(appDir, "Views", "ProcessListView.xaml");
            Assert.True(File.Exists(path));

            string content = File.ReadAllText(path);
            Assert.Contains("ScrollViewer.CanContentScroll=\"False\"", content);
            Assert.Contains("ScrollViewer.VerticalScrollBarVisibility=\"Auto\"", content);
        }

        [Fact]
        public void QuarantineView_HasSmoothScrollingConfigured()
        {
            var appDir = GetAppDir();
            var path = Path.Combine(appDir, "Views", "QuarantineView.xaml");
            Assert.True(File.Exists(path));

            string content = File.ReadAllText(path);
            Assert.Contains("ScrollViewer.CanContentScroll=\"False\"", content);
            Assert.Contains("CanContentScroll=\"False\"", content);
        }

        [Fact]
        public void BrowserSecurityAndCrashAnalysis_HaveSmoothScrollingConfigured()
        {
            var appDir = GetAppDir();
            var browserPath = Path.Combine(appDir, "Views", "BrowserSecurityView.xaml");
            Assert.True(File.Exists(browserPath));
            string browserContent = File.ReadAllText(browserPath);
            Assert.Contains("ScrollViewer.CanContentScroll=\"False\"", browserContent);

            var crashPath = Path.Combine(appDir, "Views", "CrashAnalysisView.xaml");
            Assert.True(File.Exists(crashPath));
            string crashContent = File.ReadAllText(crashPath);
            Assert.Contains("ScrollViewer.CanContentScroll=\"False\"", crashContent);
        }

        [Fact]
        public void ParentalControlsView_HasScrollViewerWrapper()
        {
            var appDir = GetAppDir();
            var path = Path.Combine(appDir, "Views", "ParentalControlsView.xaml");
            Assert.True(File.Exists(path));

            string content = File.ReadAllText(path);
            Assert.Contains("<ScrollViewer", content);
            Assert.Contains("CanContentScroll=\"False\"", content);
        }
    }
}
