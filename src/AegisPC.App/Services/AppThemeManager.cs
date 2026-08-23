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
        public static bool IsDarkMode => CurrentTheme == ThemeMode.Dark;

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

                // Auto-detect Windows System Light/Dark Mode if no explicit preference saved
                CurrentTheme = DetectWindowsSystemTheme();
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

            Application.Current?.Dispatcher?.Invoke(() =>
            {
                try
                {
                    bool dark = theme == ThemeMode.Dark;
                    var appResources = Application.Current.Resources;

                    // 1. Swap Color Token Dictionary in MergedDictionaries
                    string themeSource = dark 
                        ? "Resources/Themes/Colors.Dark.xaml" 
                        : "Resources/Themes/Colors.Light.xaml";

                    var newThemeDict = new ResourceDictionary 
                    { 
                        Source = new Uri(themeSource, UriKind.Relative) 
                    };

                    int themeDictIndex = -1;
                    for (int i = 0; i < appResources.MergedDictionaries.Count; i++)
                    {
                        var d = appResources.MergedDictionaries[i];
                        if (d.Source != null && 
                           (d.Source.OriginalString.Contains("Colors.Light.xaml", StringComparison.OrdinalIgnoreCase) || 
                            d.Source.OriginalString.Contains("Colors.Dark.xaml", StringComparison.OrdinalIgnoreCase)))
                        {
                            themeDictIndex = i;
                            break;
                        }
                    }

                    if (themeDictIndex >= 0)
                    {
                        appResources.MergedDictionaries[themeDictIndex] = newThemeDict;
                    }
                    else
                    {
                        appResources.MergedDictionaries.Add(newThemeDict);
                    }

                    // 2. Direct override update on Application.Current.Resources for all keys
                    foreach (var key in newThemeDict.Keys)
                    {
                        appResources[key] = newThemeDict[key];
                    }

                    // 3. Update WPF-UI Native Controls Palette & TitleBar
                    var textPrimary = appResources["BrushTextPrimary"] as Brush;
                    var textSecondary = appResources["BrushTextSecondary"] as Brush;
                    var textMuted = appResources["BrushTextMuted"] as Brush;
                    var cardBg = appResources["BrushCardBg"] as Brush;
                    var cardBorder = appResources["BrushCardBorder"] as Brush;
                    var appBg = appResources["BrushAppBg"] as Brush;

                    if (textPrimary != null)
                    {
                        appResources["TextFillColorPrimaryBrush"] = textPrimary;
                        appResources["TitleBarButtonForeground"] = textPrimary;
                        appResources["TitleBarButtonPointerOverForeground"] = textPrimary;
                        appResources["TitleBarButtonPressedForeground"] = textPrimary;
                    }

                    if (textSecondary != null)
                    {
                        appResources["TextFillColorSecondaryBrush"] = textSecondary;
                    }

                    if (textMuted != null)
                    {
                        appResources["TextFillColorTertiaryBrush"] = textMuted;
                    }

                    if (cardBg != null)
                    {
                        appResources["CardBackgroundSolidColorBrush"] = cardBg;
                    }

                    if (cardBorder != null)
                    {
                        appResources["CardBorderSolidColorBrush"] = cardBorder;
                    }

                    if (appBg != null)
                    {
                        appResources["NavigationViewContentBackground"] = appBg;
                        appResources["NavigationViewContentGridBackground"] = appBg;
                    }

                    // 4. Apply WPF-UI Native Theme Engine
                    ApplicationThemeManager.Apply(dark ? ApplicationTheme.Dark : ApplicationTheme.Light);
                }
                catch { }

                ThemeChanged?.Invoke(CurrentTheme);
            });
        }

        private class ThemeSettingsData
        {
            public ThemeMode Theme { get; set; } = ThemeMode.Light;
        }
    }
}
