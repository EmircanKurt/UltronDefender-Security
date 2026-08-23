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
        private static readonly SolidColorBrush EmeraldStroke = new(Color.FromRgb(0x10, 0xB9, 0x81));
        private static readonly SolidColorBrush EmeraldFill = new(Color.FromRgb(0xEC, 0xFD, 0xF5));

        private static readonly SolidColorBrush RedStroke = new(Color.FromRgb(0xEF, 0x44, 0x44));
        private static readonly SolidColorBrush RedFill = new(Color.FromRgb(0xFE, 0xF2, 0xF2));

        private static readonly SolidColorBrush OrangeStroke = new(Color.FromRgb(0xF5, 0x9E, 0x0B));
        private static readonly SolidColorBrush OrangeFill = new(Color.FromRgb(0xFF, 0xFB, 0xEB));

        private static readonly SolidColorBrush BlueStroke = new(Color.FromRgb(0x02, 0x84, 0xC7));
        private static readonly SolidColorBrush BlueFill = new(Color.FromRgb(0xF0, 0xF9, 0xFF));

        static SecurityStatusToColorConverter()
        {
            EmeraldStroke.Freeze();
            EmeraldFill.Freeze();
            RedStroke.Freeze();
            RedFill.Freeze();
            OrangeStroke.Freeze();
            OrangeFill.Freeze();
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
                return isBg ? OrangeFill : OrangeStroke;
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
