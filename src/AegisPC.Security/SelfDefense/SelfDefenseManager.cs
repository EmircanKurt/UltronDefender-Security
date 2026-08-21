using System;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AegisPC.Security.SelfDefense
{
    public static class SelfDefenseManager
    {
        private static FileStream? _executableLock;

        public static void ProtectCurrentProcess()
        {
            try
            {
                // Lock down executable from unauthorized writes/deletions while running
                string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;

                if (File.Exists(exePath) && _executableLock == null)
                {
                    // Open with FileShare.Read to prevent other non-privileged processes from deleting/overwriting
                    _executableLock = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                }
            }
            catch { }
        }

        public static bool IsTamperAttempt(string targetPath, string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return false;

            string cmd = commandLine.ToLowerInvariant();
            
            // Taskkill against Ultron / Aegis
            if (cmd.Contains("taskkill") && (cmd.Contains("ultron") || cmd.Contains("aegispc")))
            {
                return true;
            }
            
            // Service stopping or disabling
            if ((cmd.Contains("stop") || cmd.Contains("delete") || cmd.Contains("disabled")) && 
                (cmd.Contains("ultron") || cmd.Contains("aegisfilter") || cmd.Contains("aegispc")))
            {
                return true;
            }

            // PowerShell Stop-Service
            if (cmd.Contains("stop-service") && (cmd.Contains("ultron") || cmd.Contains("aegis")))
            {
                return true;
            }

            // Permission tampering (takeown / icacls deny)
            if ((cmd.Contains("takeown") || cmd.Contains("icacls")) && 
                (cmd.Contains("ultron") || cmd.Contains("aegis")))
            {
                return true;
            }

            return false;
        }
    }
}
