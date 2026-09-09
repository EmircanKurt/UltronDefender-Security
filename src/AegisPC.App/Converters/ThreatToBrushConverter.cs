using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace AegisPC.App.Converters
{
    /// <summary>
    /// Tarama sırasında tehdit durumuna göre renk geçişini yönetir:
    /// Temizken: Canlı Yeşil (#10B981)
    /// Virüs/Tehdit bulunduğunda: Marka Kırmızısı (#EF4444)
    /// </summary>
    public class ThreatToBrushConverter : IValueConverter
    {
        private static readonly SolidColorBrush SafeBrush = new(Color.FromRgb(0x10, 0xB9, 0x81));   // #10B981
        private static readonly SolidColorBrush DangerBrush = new(Color.FromRgb(0xEF, 0x44, 0x44)); // #EF4444
        private static readonly Color SafeColor = Color.FromRgb(0x10, 0xB9, 0x81);
        private static readonly Color DangerColor = Color.FromRgb(0xEF, 0x44, 0x44);

        static ThreatToBrushConverter()
        {
            SafeBrush.Freeze();
            DangerBrush.Freeze();
        }

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            bool hasThreats = false;

            if (value is bool b)
            {
                hasThreats = b;
            }
            else if (value is int count)
            {
                hasThreats = count > 0;
            }
            else if (value is long lCount)
            {
                hasThreats = lCount > 0;
            }
            else if (value is string s && int.TryParse(s, out int parsed))
            {
                hasThreats = parsed > 0;
            }

            string param = parameter?.ToString()?.Trim().ToLowerInvariant() ?? "brush";

            if (param == "color" || targetType == typeof(Color))
            {
                return hasThreats ? DangerColor : SafeColor;
            }

            // Default: SolidColorBrush
            return hasThreats ? DangerBrush : SafeBrush;
        }

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
