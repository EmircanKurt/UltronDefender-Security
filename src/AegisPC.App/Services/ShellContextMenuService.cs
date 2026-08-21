using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AegisPC.App.Services
{
    public static class ShellContextMenuService
    {
        private const string MenuKeyName = "UltronDefenderScan";
        private const string MenuText = "🛡️ Ultron Defender ile Tara";

        public static void EnsureRegistered()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

            try
            {
                string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
                if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                {
                    var baseDir = AppDomain.CurrentDomain.BaseDirectory;
                    exePath = Path.Combine(baseDir, "UltronDefender.exe");
                    if (!File.Exists(exePath))
                    {
                        exePath = Path.Combine(baseDir, "Ultron Defender Security.exe");
                    }
                }

                if (!File.Exists(exePath)) return;

                // Clean up any old unsafe overrides
                UnregisterKey(@"Software\Classes\Folder\shell");
                UnregisterKey(@"Software\Classes\AllFilesystemObjects\shell");
                UnregisterKey(@"Software\Classes\Drive\shell");

                // Standard, safe context menu verbs
                RegisterKey(@"Software\Classes\*\shell", exePath, "\"%1\"");
                RegisterKey(@"Software\Classes\Directory\shell", exePath, "\"%1\"");
                RegisterKey(@"Software\Classes\Directory\Background\shell", exePath, "\"%V\"");
            }
            catch { }
        }

        private static void RegisterKey(string parentSubKey, string exePath, string argPlaceholder)
        {
            try
            {
                using var parent = Registry.CurrentUser.CreateSubKey(parentSubKey, true);
                if (parent == null) return;

                using var menuKey = parent.CreateSubKey(MenuKeyName, true);
                if (menuKey == null) return;

                menuKey.SetValue(string.Empty, MenuText);
                menuKey.SetValue("Icon", $"\"{exePath}\",0");

                using var cmdKey = menuKey.CreateSubKey("command", true);
                if (cmdKey == null) return;

                cmdKey.SetValue(string.Empty, $"\"{exePath}\" /scan {argPlaceholder}");
            }
            catch { }
        }

        public static void Unregister()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

            try
            {
                UnregisterKey(@"Software\Classes\*\shell");
                UnregisterKey(@"Software\Classes\Directory\shell");
                UnregisterKey(@"Software\Classes\Directory\Background\shell");
                UnregisterKey(@"Software\Classes\Folder\shell");
                UnregisterKey(@"Software\Classes\Drive\shell");
                UnregisterKey(@"Software\Classes\AllFilesystemObjects\shell");
            }
            catch { }
        }

        private static void UnregisterKey(string parentSubKey)
        {
            try
            {
                using var parent = Registry.CurrentUser.OpenSubKey(parentSubKey, true);
                parent?.DeleteSubKeyTree(MenuKeyName, false);
            }
            catch { }
        }
    }
}