using System;
using System.IO;
using System.Linq;

namespace AegisPC.Performance.Monitoring
{
    /// <summary>
    /// Measures disk storage capacity and free space across all ready fixed drives.
    /// </summary>
    public class DiskMonitor
    {
        public (long totalBytes, long freeBytes, long usedBytes, double usagePercent) GetTotalDiskMetrics()
        {
            long total = 0;
            long free = 0;

            try
            {
                var drives = DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed);
                foreach (var drive in drives)
                {
                    total += drive.TotalSize;
                    free += drive.AvailableFreeSpace;
                }
            }
            catch
            {
                // Fallback for restricted environments
            }

            long used = Math.Max(0, total - free);
            double percent = total > 0 ? ((double)used / total) * 100.0 : 0.0;

            return (total, free, used, Math.Round(percent, 1));
        }
    }
}
