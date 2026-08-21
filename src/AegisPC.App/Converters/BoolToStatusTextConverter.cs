using System;
using System.Globalization;
using System.Windows.Data;

namespace AegisPC.App.Converters
{
    public class BoolToStatusTextConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            bool isTrue = false;
            if (value is bool b)
            {
                isTrue = b;
            }
            else if (value != null && bool.TryParse(value.ToString(), out bool parsed))
            {
                isTrue = parsed;
            }

            string mode = parameter?.ToString()?.ToLowerInvariant() ?? "enabled";

            return mode switch
            {
                "yesno" => isTrue ? "Evet" : "Hayır",
                "onoff" => isTrue ? "Açık" : "Kapalı",
                "active" => isTrue ? "Aktif" : "Pasif",
                _ => isTrue ? "Etkin" : "Devre Dışı"
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
