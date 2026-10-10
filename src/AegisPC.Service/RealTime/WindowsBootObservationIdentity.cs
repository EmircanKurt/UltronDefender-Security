using System.Globalization;
using System.Management;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.RealTime;

/// <summary>Read-only OS-reported boot epoch for local observation correlation, not native authorization.</summary>
internal static class WindowsBootObservationIdentity
{
    internal static string Resolve(ILogger? logger)
    {
        try
        {
            using var query = new ManagementObjectSearcher("SELECT LastBootUpTime FROM Win32_OperatingSystem");
            using var result = query.Get();
            foreach (ManagementObject os in result)
            {
                using (os)
                    if (os["LastBootUpTime"] is string value)
                        return "os-boot-utc:" + ManagementDateTimeConverter.ToDateTime(value).ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
            }
        }
        catch (Exception ex) { logger?.LogWarning("OS boot identity unavailable ({FailureType}); attribution stays unknown.", ex.GetType().Name); }
        return string.Empty;
    }
}
