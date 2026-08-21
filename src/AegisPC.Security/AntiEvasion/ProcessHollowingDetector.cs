using System;
using System.Diagnostics;
using System.IO;

namespace AegisPC.Security.AntiEvasion
{
    public static class ProcessHollowingDetector
    {
        public static bool CheckProcessIntegrity(int pid, string expectedImagePath)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                if (proc.HasExited) return false;

                string currentImage = proc.MainModule?.FileName ?? string.Empty;
                if (!string.IsNullOrEmpty(currentImage) && !string.IsNullOrEmpty(expectedImagePath))
                {
                    if (!currentImage.Equals(expectedImagePath, StringComparison.OrdinalIgnoreCase))
                    {
                        return true; // Process path mismatch
                    }
                }
            }
            catch { }

            return false;
        }
    }
}
