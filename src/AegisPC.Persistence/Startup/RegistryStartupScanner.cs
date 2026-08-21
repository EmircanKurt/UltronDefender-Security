using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Win32;

namespace AegisPC.Persistence.Startup
{
    public static class RegistryStartupScanner
    {
        private static readonly string[] RunKeyPaths = new[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
        };

        private static readonly string PersistentDisabledFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AegisPC",
            "disabled_startup.json");

        public static HashSet<string> LoadPersistentDisabledItems()
        {
            try
            {
                if (File.Exists(PersistentDisabledFile))
                {
                    var json = File.ReadAllText(PersistentDisabledFile);
                    var set = JsonSerializer.Deserialize<HashSet<string>>(json);
                    if (set != null) return set;
                }
            }
            catch { }
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        public static void SavePersistentDisabledItems(HashSet<string> set)
        {
            try
            {
                var dir = Path.GetDirectoryName(PersistentDisabledFile);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                var json = JsonSerializer.Serialize(set);
                File.WriteAllText(PersistentDisabledFile, json);
            }
            catch { }
        }

        public static List<StartupItem> ScanRegistryStartup()
        {
            var items = new List<StartupItem>();
            var disabledSet = LoadPersistentDisabledItems();
            var approvedDisabled = GetStartupApprovedDisabledNames();

            // 1. Current User (HKCU)
            foreach (var subKeyPath in RunKeyPaths)
            {
                using var key = Registry.CurrentUser.OpenSubKey(subKeyPath);
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        var rawValue = key.GetValue(valueName)?.ToString() ?? string.Empty;
                        var (filePath, args) = ParseCommand(rawValue);

                        bool isItemDisabled = disabledSet.Contains(valueName) || 
                                              disabledSet.Contains(filePath) || 
                                              approvedDisabled.Contains(valueName);

                        items.Add(new StartupItem
                        {
                            Name = valueName,
                            FilePath = filePath,
                            Arguments = args,
                            Source = $"Kayıt Defteri (HKCU\\{subKeyPath})",
                            RegistryPath = $"HKCU\\{subKeyPath}",
                            IsEnabled = !isItemDisabled,
                            RiskLevel = RiskLevel.Clean,
                            ImpactLevel = ImpactLevel.Medium
                        });
                    }
                }
            }

            // 2. Local Machine (HKLM 64-bit and 32-bit)
            var views = new[] { RegistryView.Registry64, RegistryView.Registry32 };
            foreach (var view in views)
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                foreach (var subKeyPath in RunKeyPaths)
                {
                    using var key = baseKey.OpenSubKey(subKeyPath);
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            var rawValue = key.GetValue(valueName)?.ToString() ?? string.Empty;
                            var (filePath, args) = ParseCommand(rawValue);

                            bool isItemDisabled = disabledSet.Contains(valueName) || 
                                                  disabledSet.Contains(filePath) || 
                                                  approvedDisabled.Contains(valueName);

                            items.Add(new StartupItem
                            {
                                Name = valueName,
                                FilePath = filePath,
                                Arguments = args,
                                Source = $"Kayıt Defteri (HKLM\\{subKeyPath}) [{(view == RegistryView.Registry64 ? "64-bit" : "32-bit")}]",
                                RegistryPath = $"HKLM\\{subKeyPath}",
                                IsEnabled = !isItemDisabled,
                                RiskLevel = RiskLevel.Clean,
                                ImpactLevel = ImpactLevel.Medium
                            });
                        }
                    }
                }
            }

            return items;
        }

        private static HashSet<string> GetStartupApprovedDisabledNames()
        {
            var disabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run");
                if (key != null)
                {
                    foreach (var name in key.GetValueNames())
                    {
                        var bytes = key.GetValue(name) as byte[];
                        if (bytes != null && bytes.Length > 0 && bytes[0] != 0x02) // 0x02 is enabled, 0x03+ is disabled
                        {
                            disabled.Add(name);
                        }
                    }
                }
            }
            catch { }
            return disabled;
        }

        private static (string filePath, string? args) ParseCommand(string rawCommand)
        {
            if (string.IsNullOrWhiteSpace(rawCommand)) return (string.Empty, null);

            rawCommand = rawCommand.Trim();
            if (rawCommand.StartsWith("\""))
            {
                var endQuote = rawCommand.IndexOf('"', 1);
                if (endQuote > 0)
                {
                    var file = rawCommand.Substring(1, endQuote - 1);
                    var args = rawCommand.Length > endQuote + 1 ? rawCommand.Substring(endQuote + 1).Trim() : null;
                    return (file, string.IsNullOrEmpty(args) ? null : args);
                }
            }

            var parts = rawCommand.Split(' ', 2);
            return (parts[0], parts.Length > 1 ? parts[1].Trim() : null);
        }
    }
}
