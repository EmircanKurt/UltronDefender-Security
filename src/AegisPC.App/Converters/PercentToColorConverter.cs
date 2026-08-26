using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace AegisPC.App.Converters
{
    public class PercentToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is int percent)
            {
                if (percent >= 85) return new SolidColorBrush(Color.FromRgb(0x4C, 0xAF, 0x50)); // Safe Green
                if (percent >= 70) return new SolidColorBrush(Color.FromRgb(0xF5, 0xA6, 0x23)); // Amber
                if (percent >= 50) return new SolidColorBrush(Color.FromRgb(0xD9, 0x38, 0x1E)); // High Risk
                return new SolidColorBrush(Color.FromRgb(0xC4, 0x1E, 0x1E)); // Danger Red
            }
            return new SolidColorBrush(Color.FromRgb(0x8B, 0x95, 0xA3));
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
