using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Win32;

namespace AegisPC.BrowserSecurity.Applications
{
    public static class ApplicationInventoryScanner
    {
        public static List<InstalledApplication> ScanInstalledApplications()
        {
            var apps = new Dictionary<string, InstalledApplication>(StringComparer.OrdinalIgnoreCase);

            // 1. HKCU Uninstall
            ScanRegistryKey(RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\Uninstall", apps);

            // 2. HKLM 64-bit Uninstall
            ScanRegistryKey(RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows\CurrentVersion\Uninstall", apps);

            // 3. HKLM 32-bit (WoW6432Node) Uninstall
            ScanRegistryKey(RegistryHive.LocalMachine, RegistryView.Registry32, @"Software\Microsoft\Windows\CurrentVersion\Uninstall", apps);

            return apps.Values.OrderBy(a => a.DisplayName).ToList();
        }

        private static void ScanRegistryKey(RegistryHive hive, RegistryView view, string subKeyPath, Dictionary<string, InstalledApplication> apps)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var uninstallKey = baseKey.OpenSubKey(subKeyPath);
                if (uninstallKey == null) return;

                foreach (var appKeyName in uninstallKey.GetSubKeyNames())
                {
                    try
                    {
                        using var appKey = uninstallKey.OpenSubKey(appKeyName);
                        if (appKey == null) continue;

                        var displayName = appKey.GetValue("DisplayName")?.ToString();
                        if (string.IsNullOrWhiteSpace(displayName)) continue; // Skip entries without visible names

                        // Skip Windows Updates and Hotfixes
                        if (appKey.GetValue("ParentKeyName") != null || displayName.StartsWith("KB", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        var publisher = appKey.GetValue("Publisher")?.ToString();
                        var version = appKey.GetValue("DisplayVersion")?.ToString();
                        var installDateStr = appKey.GetValue("InstallDate")?.ToString();
                        var installLocation = appKey.GetValue("InstallLocation")?.ToString();
                        var uninstallString = appKey.GetValue("UninstallString")?.ToString();
                        var displayIcon = appKey.GetValue("DisplayIcon")?.ToString();
                        var sizeObj = appKey.GetValue("EstimatedSize");
                        long sizeKb = 0;
                        if (sizeObj != null && long.TryParse(sizeObj.ToString(), out var parsedSize))
                        {
                            sizeKb = parsedSize;
                        }

                        DateTime? installDate = null;
                        if (!string.IsNullOrEmpty(installDateStr) && installDateStr.Length == 8)
                        {
                            if (int.TryParse(installDateStr.Substring(0, 4), out int year) &&
                                int.TryParse(installDateStr.Substring(4, 2), out int month) &&
                                int.TryParse(installDateStr.Substring(6, 2), out int day))
                            {
                                installDate = new DateTime(year, month, day);
                            }
                        }

                        var app = new InstalledApplication
                        {
                            DisplayName = displayName,
                            Publisher = publisher,
                            Version = version,
                            InstallDate = installDate,
                            EstimatedSizeKB = sizeKb,
                            InstallLocation = installLocation,
                            UninstallString = uninstallString,
                            DisplayIcon = displayIcon,
                            RegistrySource = $"{hive}\\{subKeyPath}",
                            TrustLevel = 0
                        };

                        apps[displayName] = app;
                    }
                    catch { }
                }
            }
            catch { }
        }
    }
}
