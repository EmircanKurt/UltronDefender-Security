using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace AegisPC.App.Converters
{
    /// <summary>
    /// Eklenti açıklamasının dolu ve geçerli bir metin olup olmadığını denetler.
    /// Boş, MSG_ yer tutucusu veya 'Açıklama yok' ise alanı gizler.
    /// </summary>
    public class DescriptionVisibilityConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is string text)
            {
                var trimmed = text.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) return Visibility.Collapsed;
                if (trimmed.StartsWith("__MSG_", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.StartsWith("MSG_", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Equals("Açıklama yok", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Equals("No description", StringComparison.OrdinalIgnoreCase))
                {
                    return Visibility.Collapsed;
                }
                return Visibility.Visible;
            }
            return Visibility.Collapsed;
        }

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
