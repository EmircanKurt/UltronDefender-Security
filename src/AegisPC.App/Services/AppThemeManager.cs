using System;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using AegisPC.Core.Enums;
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
                    }
                }
            }
            catch { }
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
                    var res = Application.Current.Resources;
                    bool dark = theme == ThemeMode.Dark;

                    // Core Dynamic Palette Tokens
                    Color colorAppBg = dark ? Color.FromRgb(11, 15, 25) : Color.FromRgb(238, 242, 246); // #0B0F19 vs #EEF2F6
                    Color colorCardBg = dark ? Color.FromRgb(17, 24, 39) : Color.FromRgb(255, 255, 255); // #111827 vs #FFFFFF
                    Color colorCardBgAlt = dark ? Color.FromRgb(22, 32, 50) : Color.FromRgb(248, 250, 252); // #162032 vs #F8FAFC
                    Color colorCardBorder = dark ? Color.FromRgb(30, 41, 59) : Color.FromRgb(226, 232, 240); // #1E293B vs #E2E8F0
                    Color colorCardBorderHover = dark ? Color.FromRgb(59, 130, 246) : Color.FromRgb(203, 213, 225); // #3B82F6 vs #CBD5E1

                    Color colorTextPrimary = dark ? Color.FromRgb(248, 250, 252) : Color.FromRgb(15, 23, 42); // #F8FAFC vs #0F172A
                    Color colorTextSecondary = dark ? Color.FromRgb(203, 213, 225) : Color.FromRgb(71, 85, 105); // #CBD5E1 vs #475569
                    Color colorTextMuted = dark ? Color.FromRgb(148, 163, 184) : Color.FromRgb(100, 116, 139); // #94A3B8 vs #64748B

                    Color colorSidebarBg = dark ? Color.FromRgb(7, 11, 20) : Color.FromRgb(10, 15, 29); // #070B14 vs #0A0F1D

                    // Update Dynamic Resources in Application
                    res["ColorAppBg"] = colorAppBg;
                    res["ColorCardBg"] = colorCardBg;
                    res["ColorCardBgAlt"] = colorCardBgAlt;
                    res["ColorCardBorder"] = colorCardBorder;
                    res["ColorCardBorderHover"] = colorCardBorderHover;

                    res["ColorTextPrimary"] = colorTextPrimary;
                    res["ColorTextSecondary"] = colorTextSecondary;
                    res["ColorTextMuted"] = colorTextMuted;

                    // Update Solid Color Brushes
                    res["BrushAppBg"] = new SolidColorBrush(colorAppBg);
                    res["BrushCardBg"] = new SolidColorBrush(colorCardBg);
                    res["BrushCardBgAlt"] = new SolidColorBrush(colorCardBgAlt);
                    res["BrushCardBorder"] = new SolidColorBrush(colorCardBorder);
                    res["BrushSidebarBg"] = new SolidColorBrush(colorSidebarBg);

                    res["BrushTextPrimary"] = new SolidColorBrush(colorTextPrimary);
                    res["BrushTextSecondary"] = new SolidColorBrush(colorTextSecondary);
                    res["BrushTextMuted"] = new SolidColorBrush(colorTextMuted);

                    // Update TitleBar Brushes
                    res["TitleBarButtonForeground"] = new SolidColorBrush(colorTextPrimary);
                    res["TitleBarButtonPointerOverForeground"] = new SolidColorBrush(colorTextPrimary);
                    res["TitleBarButtonPointerOverBackground"] = new SolidColorBrush(dark ? Color.FromRgb(30, 41, 59) : Color.FromRgb(226, 232, 240));
                    res["TitleBarButtonPressedForeground"] = new SolidColorBrush(colorTextPrimary);
                    res["TitleBarButtonPressedBackground"] = new SolidColorBrush(dark ? Color.FromRgb(51, 65, 85) : Color.FromRgb(203, 213, 225));

                    // Update WPF-UI Native Controls Brushes
                    res["CardBackgroundSolidColorBrush"] = new SolidColorBrush(colorCardBg);
                    res["CardBorderSolidColorBrush"] = new SolidColorBrush(colorCardBorder);
                    res["TextFillColorPrimaryBrush"] = new SolidColorBrush(colorTextPrimary);
                    res["TextFillColorSecondaryBrush"] = new SolidColorBrush(colorTextSecondary);
                    res["TextFillColorTertiaryBrush"] = new SolidColorBrush(colorTextMuted);

                    res["NavigationViewContentBackground"] = new SolidColorBrush(colorAppBg);
                    res["NavigationViewContentGridBackground"] = new SolidColorBrush(colorAppBg);

                    // Apply WPF-UI Theme
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
