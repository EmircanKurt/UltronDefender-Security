using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using AegisPC.Core.Enums;

namespace AegisPC.App.Converters
{
    public class RiskLevelToColorConverter : IValueConverter
    {
        private static readonly SolidColorBrush SafeGreenBrush = new(Color.FromRgb(0x4C, 0xAF, 0x50));
        private static readonly SolidColorBrush LowRiskBlueBrush = new(Color.FromRgb(0x3B, 0x82, 0xF6));
        private static readonly SolidColorBrush SuspiciousAmberBrush = new(Color.FromRgb(0xF5, 0xA6, 0x23));
        private static readonly SolidColorBrush HighRiskOrangeBrush = new(Color.FromRgb(0xEA, 0x58, 0x0C));
        private static readonly SolidColorBrush CriticalRedBrush = new(Color.FromRgb(0xC4, 0x1E, 0x1E));
        private static readonly SolidColorBrush SlateMutedBrush = new(Color.FromRgb(0x8B, 0x95, 0xA3));

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            RiskLevel? risk = value switch
            {
                RiskLevel rl => rl,
                int i when Enum.IsDefined(typeof(RiskLevel), i) => (RiskLevel)i,
                string s when Enum.TryParse<RiskLevel>(s, true, out var parsed) => parsed,
                _ => null
            };

            if (risk.HasValue)
            {
                return risk.Value switch
                {
                    RiskLevel.Clean => SafeGreenBrush,
                    RiskLevel.LowRisk => LowRiskBlueBrush,
                    RiskLevel.Suspicious => SuspiciousAmberBrush,
                    RiskLevel.HighRisk => HighRiskOrangeBrush,
                    RiskLevel.ConfirmedMalicious => CriticalRedBrush,
                    _ => SlateMutedBrush
                };
            }

            return SlateMutedBrush;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
