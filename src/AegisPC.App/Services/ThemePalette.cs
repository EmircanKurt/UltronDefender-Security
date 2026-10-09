using System.Windows;
using System.Windows.Media;

namespace AegisPC.App.Services;

/// <summary>Applies the exact production palette without persisting preferences or starting an application.</summary>
public static class ThemePalette
{
    /// <summary>Refreshes merged and direct native keys together, including brushes left by an earlier theme.</summary>
    public static void Apply(ResourceDictionary resources, bool dark)
    {
        ArgumentNullException.ThrowIfNull(resources);
        var palette = new ResourceDictionary { Source = new Uri(
            $"/UltronDefender;component/Resources/Themes/Colors.{(dark ? "Dark" : "Light")}.xaml", UriKind.Relative) };
        var previous = resources.MergedDictionaries.FirstOrDefault(d => d.Source?.OriginalString.Contains("Colors.Light.xaml", StringComparison.OrdinalIgnoreCase) == true ||
            d.Source?.OriginalString.Contains("Colors.Dark.xaml", StringComparison.OrdinalIgnoreCase) == true);
        if (previous != null) resources.MergedDictionaries[resources.MergedDictionaries.IndexOf(previous)] = palette;
        else resources.MergedDictionaries.Add(palette);
        foreach (var key in palette.Keys) resources[key] = palette[key];

        void Alias(string source, params string[] targets)
        {
            if (resources[source] is not Brush brush) return;
            foreach (var target in targets) resources[target] = brush;
        }
        Alias("BrushTextPrimary", "TextFillColorPrimaryBrush", "TitleBarButtonForeground", "TitleBarButtonPointerOverForeground", "TitleBarButtonPressedForeground");
        Alias("BrushTextSecondary", "TextFillColorSecondaryBrush");
        Alias("BrushTextMuted", "TextFillColorTertiaryBrush");
        Alias("BrushCardBg", "CardBackgroundSolidColorBrush");
        Alias("BrushCardBorder", "CardBorderSolidColorBrush");
        Alias("BrushAppBg", "NavigationViewContentBackground", "NavigationViewContentGridBackground");
        Alias("BrushSidebarBg", "NavigationViewPaneBackground", "NavigationViewDefaultPaneBackground", "NavigationViewExpandedPaneBackground");
    }
}
