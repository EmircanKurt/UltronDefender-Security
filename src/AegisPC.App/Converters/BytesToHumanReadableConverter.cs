using System;
using System.Globalization;
using System.Windows.Data;

namespace AegisPC.App.Converters
{
    public class BytesToHumanReadableConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is long byteCount)
            {
                string[] suf = { "B", "KB", "MB", "GB", "TB", "PB", "EB" }; //Longs run out around EB
                if (byteCount == 0)
                    return "0" + suf[0];
                long bytes = Math.Abs(byteCount);
                int place = System.Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
                double num = Math.Round(bytes / Math.Pow(1024, place), 1);
                return (Math.Sign(byteCount) * num).ToString() + " " + suf[place];
            }
            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
