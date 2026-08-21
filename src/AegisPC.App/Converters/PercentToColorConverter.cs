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
                if (percent >= 85) return new SolidColorBrush(Color.FromRgb(46, 204, 113)); // Green
                if (percent >= 70) return new SolidColorBrush(Color.FromRgb(241, 196, 15)); // Yellow
                if (percent >= 50) return new SolidColorBrush(Color.FromRgb(230, 126, 34)); // Orange
                return new SolidColorBrush(Color.FromRgb(231, 76, 60)); // Red
            }
            return new SolidColorBrush(Colors.Gray);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
