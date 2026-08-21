using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace AegisPC.App.Converters
{
    public class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            bool isTrue = false;
            if (value is bool b)
            {
                isTrue = b;
            }
            else if (value != null)
            {
                isTrue = true;
            }

            if (parameter is string paramStr && paramStr.Equals("Inverse", StringComparison.OrdinalIgnoreCase))
            {
                isTrue = !isTrue;
            }

            if (targetType == typeof(bool))
            {
                return isTrue;
            }

            return isTrue ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is Visibility v)
            {
                bool result = v == Visibility.Visible;
                if (parameter is string paramStr && paramStr.Equals("Inverse", StringComparison.OrdinalIgnoreCase))
                {
                    result = !result;
                }
                return result;
            }
            if (value is bool b)
            {
                return b;
            }
            return false;
        }
    }
}
