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
                    0 => new SolidColorBrush(Colors.Green),
                    1 => new SolidColorBrush(Colors.Gold),
                    2 => new SolidColorBrush(Colors.Orange),
                    3 => new SolidColorBrush(Colors.Red),
                    _ => new SolidColorBrush(Colors.Gray)
                };
            }
            return new SolidColorBrush(Colors.Gray);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
