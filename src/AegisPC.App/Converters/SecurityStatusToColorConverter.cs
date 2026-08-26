using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace AegisPC.App.Converters
{
    /// <summary>
    /// Güvenlik durum metnini, risk seviyesini veya renk kodunu dinamik SolidColorBrush / Color nesnesine dönüştüren merkezi dönüştürücü.
    /// Desteklenen parametreler:
    /// - "Border" veya "Stroke": Ana durum rengi (Yeşil #10B981, Kırmızı #EF4444, Turuncu #F59E0B, Mavi #0284C7)
    /// - "Background" veya "Fill": Hafif tonlu arka plan dolgu rengi (Örn: Açık yeşil #ECFDF5, Açık kırmızı #FEF2F2)
    /// </summary>
    public class SecurityStatusToColorConverter : IValueConverter
    {
        private static readonly SolidColorBrush EmeraldStroke = new(Color.FromRgb(0x4C, 0xAF, 0x50));
        private static readonly SolidColorBrush EmeraldFill = new(Color.FromRgb(0x12, 0x2A, 0x1C));

        private static readonly SolidColorBrush RedStroke = new(Color.FromRgb(0xC4, 0x1E, 0x1E));
        private static readonly SolidColorBrush RedFill = new(Color.FromRgb(0x2A, 0x12, 0x15));

        private static readonly SolidColorBrush AmberStroke = new(Color.FromRgb(0xF5, 0xA6, 0x23));
        private static readonly SolidColorBrush AmberFill = new(Color.FromRgb(0x2D, 0x20, 0x0E));

        private static readonly SolidColorBrush BlueStroke = new(Color.FromRgb(0x21, 0x96, 0xF3));
        private static readonly SolidColorBrush BlueFill = new(Color.FromRgb(0x11, 0x23, 0x38));

        static SecurityStatusToColorConverter()
        {
            EmeraldStroke.Freeze();
            EmeraldFill.Freeze();
            RedStroke.Freeze();
            RedFill.Freeze();
            AmberStroke.Freeze();
            AmberFill.Freeze();
            BlueStroke.Freeze();
            BlueFill.Freeze();
        }

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            string strValue = value?.ToString()?.Trim() ?? string.Empty;
            string param = parameter?.ToString()?.Trim().ToLowerInvariant() ?? "stroke";

            bool isBg = param is "background" or "fill" or "bg";

            // Check if input is already a hex color string
            if (strValue.StartsWith("#"))
            {
                try
                {
                    var color = (Color)ColorConverter.ConvertFromString(strValue);
                    if (isBg)
                    {
                        // Generate soft pastel background tint (85% alpha or 15% opacity overlay)
                        var bgTint = Color.FromArgb(0x1E, color.R, color.G, color.B);
                        var bgBrush = new SolidColorBrush(bgTint);
                        bgBrush.Freeze();
                        return bgBrush;
                    }
                    var strokeBrush = new SolidColorBrush(color);
                    strokeBrush.Freeze();
                    return strokeBrush;
                }
                catch
                {
                    // Fallback to default
                }
            }

            // Status Text Matches
            if (strValue.Contains("TEHDİT", StringComparison.OrdinalIgnoreCase) ||
                strValue.Contains("DANGER", StringComparison.OrdinalIgnoreCase) ||
                strValue.Contains("MALICIOUS", StringComparison.OrdinalIgnoreCase) ||
                strValue.Contains("CRITICAL", StringComparison.OrdinalIgnoreCase) ||
                strValue.Contains("DEGRADED", StringComparison.OrdinalIgnoreCase))
            {
                return isBg ? RedFill : RedStroke;
            }

            if (strValue.Contains("ŞÜPHELİ", StringComparison.OrdinalIgnoreCase) ||
                strValue.Contains("WARNING", StringComparison.OrdinalIgnoreCase) ||
                strValue.Contains("SUSPICIOUS", StringComparison.OrdinalIgnoreCase) ||
                strValue.Contains("HAZIRLANIYOR", StringComparison.OrdinalIgnoreCase))
            {
                return isBg ? AmberFill : AmberStroke;
            }

            if (strValue.Contains("TARANIYOR", StringComparison.OrdinalIgnoreCase) ||
                strValue.Contains("SCANNING", StringComparison.OrdinalIgnoreCase) ||
                strValue.Contains("INFO", StringComparison.OrdinalIgnoreCase))
            {
                return isBg ? BlueFill : BlueStroke;
            }

            // Clean / Güvendesiniz / Protected default
            return isBg ? EmeraldFill : EmeraldStroke;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
