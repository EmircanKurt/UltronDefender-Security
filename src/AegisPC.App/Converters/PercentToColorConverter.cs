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
            double percent = 0.0;
            if (value is double d) percent = d;
            else if (value is int i) percent = i;
            else if (value is float f) percent = f;
            else if (value is long l) percent = l;
            else if (value != null && double.TryParse(value.ToString(), out double parsed)) percent = parsed;

            // Parameter "Health": 100 is safe green, 0 is danger red.
            // Default "Usage": <70 is safe green, 70-85 is amber warning, >85 is danger red.
            bool isHealth = parameter?.ToString()?.Equals("Health", StringComparison.OrdinalIgnoreCase) == true;

            if (isHealth)
            {
                if (percent >= 85) return new SolidColorBrush(Color.FromRgb(0x10, 0xB9, 0x81)); // Safe Green
                if (percent >= 70) return new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)); // Amber
                return new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44)); // Danger Red
            }
            else
            {
                // Usage metric (Disk, CPU, RAM): Low is Safe Green, High is Danger Red
                if (percent >= 85) return new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44)); // Danger Red
                if (percent >= 70) return new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)); // Amber Warning
                return new SolidColorBrush(Color.FromRgb(0x10, 0xB9, 0x81)); // Safe Green
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
