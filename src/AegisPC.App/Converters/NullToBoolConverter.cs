using System;
using System.Globalization;
using System.Windows.Data;

namespace AegisPC.App.Converters
{
    public class NullToBoolConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            bool isNotNull = value != null;
            if (parameter is string p && p.Equals("Inverse", StringComparison.OrdinalIgnoreCase))
            {
                return !isNotNull;
            }
            return isNotNull;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
