using System;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using AegisPC.Core.Enums;
using Microsoft.Win32;
using Wpf.Ui.Appearance;

namespace AegisPC.App.Services
{
    public static class AppThemeManager
    {
        private static readonly string SettingsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "UltronDefender",
            "theme_settings.json");

        public static ThemeMode CurrentTheme { get; private set; } = ThemeMode.Light;
        public static bool IsDarkMode
        {
            get
            {
                if (CurrentTheme == ThemeMode.Dark) return true;
                if (CurrentTheme == ThemeMode.System) return DetectWindowsSystemTheme() == ThemeMode.Dark;
                return false;
            }
        }

        public static event Action<ThemeMode>? ThemeChanged;

        static AppThemeManager()
        {
            LoadSavedTheme();
        }

        public static void LoadSavedTheme()
        {
            try
            {
                if (File.Exists(SettingsPath))
                {
                    string json = File.ReadAllText(SettingsPath);
                    var data = JsonSerializer.Deserialize<ThemeSettingsData>(json);
                    if (data != null)
                    {
                        CurrentTheme = data.Theme;
                        return;
                    }
                }

                // New installations use the plain light design; explicit saved preferences remain intact.
                CurrentTheme = ThemeMode.Light;
            }
            catch
            {
                CurrentTheme = ThemeMode.Light;
            }
        }

        public static ThemeMode DetectWindowsSystemTheme()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
                if (key != null)
                {
                    var appsUseLightTheme = key.GetValue("AppsUseLightTheme");
                    if (appsUseLightTheme is int val && val == 0)
                    {
                        return ThemeMode.Dark;
                    }
                }
            }
            catch { }

            return ThemeMode.Light;
        }

        public static void SaveTheme(ThemeMode theme)
        {
            try
            {
                string dir = Path.GetDirectoryName(SettingsPath)!;
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

                string json = JsonSerializer.Serialize(new ThemeSettingsData { Theme = theme });
                File.WriteAllText(SettingsPath, json);
            }
            catch { }
        }

        public static void ToggleTheme()
        {
            ApplyTheme(IsDarkMode ? ThemeMode.Light : ThemeMode.Dark);
        }

        public static void ApplyTheme(ThemeMode theme)
        {
            CurrentTheme = theme;
            SaveTheme(theme);

            Action applyAction = () =>
            {
                try
                {
                    bool isSystemDark = DetectWindowsSystemTheme() == ThemeMode.Dark;
                    bool dark = (theme == ThemeMode.Dark) || (theme == ThemeMode.System && isSystemDark);
                    var appResources = Application.Current?.Resources;
                    if (appResources == null) return;

                    // 1. Apply WPF-UI Native Theme Engine first so custom tokens take precedence
                    try
                    {
                        ApplicationThemeManager.Apply(dark ? ApplicationTheme.Dark : ApplicationTheme.Light);
                    }
                    catch { }

                    ThemePalette.Apply(appResources, dark);
                }
                catch { }

                ThemeChanged?.Invoke(CurrentTheme);
            };

            var app = Application.Current;
            var dispatcher = app?.Dispatcher;
            if (dispatcher != null && dispatcher.Thread.IsAlive && !dispatcher.HasShutdownStarted)
            {
                if (dispatcher.CheckAccess())
                {
                    applyAction();
                }
                else
                {
                    dispatcher.BeginInvoke(applyAction);
                }
            }
            else
            {
                applyAction();
            }
        }

        private class ThemeSettingsData
        {
            public ThemeMode Theme { get; set; } = ThemeMode.Light;
        }
    }
}
