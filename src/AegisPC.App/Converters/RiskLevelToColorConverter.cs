using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace AegisPC.App.Converters
{
    public class RiskLevelToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is int level)
            {
                return level switch
                {
                    0 => new SolidColorBrush(Color.FromRgb(0x4C, 0xAF, 0x50)), // Safe Green
                    1 => new SolidColorBrush(Color.FromRgb(0xF5, 0xA6, 0x23)), // Amber Warning
                    2 => new SolidColorBrush(Color.FromRgb(0xD9, 0x38, 0x1E)), // High Risk
                    3 => new SolidColorBrush(Color.FromRgb(0xC4, 0x1E, 0x1E)), // Critical Danger Red
                    _ => new SolidColorBrush(Color.FromRgb(0x8B, 0x95, 0xA3))  // Slate Muted
                };
            }
            return new SolidColorBrush(Colors.Gray);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
