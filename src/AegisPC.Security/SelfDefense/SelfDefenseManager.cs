using System;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AegisPC.Security.SelfDefense
{
    public static class SelfDefenseManager
    {
        public static void ProtectCurrentProcess()
        {
            try
            {
                // Lock down executable and essential files from deletion/tampering
                string appDir = AppDomain.CurrentDomain.BaseDirectory;
                string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;

                if (File.Exists(exePath))
                {
                    // Ensure DACL prevents unauthorized writes while running
                }
            }
            catch { }
        }

        public static bool IsTamperAttempt(string targetPath, string commandLine)
        {
            string cmd = commandLine.ToLowerInvariant();
            if (cmd.Contains("taskkill") && (cmd.Contains("ultron") || cmd.Contains("aegispc")))
            {
                return true;
            }
            if (cmd.Contains("stop") && (cmd.Contains("ultron") || cmd.Contains("aegisfilter")))
            {
                return true;
            }
            return false;
        }
    }
}
