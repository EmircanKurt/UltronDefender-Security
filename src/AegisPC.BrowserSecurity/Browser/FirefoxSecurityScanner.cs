using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.BrowserSecurity.Browser
{
    public static class FirefoxSecurityScanner
    {
        public static List<BrowserProfile> ScanFirefoxProfiles()
        {
            var profiles = new List<BrowserProfile>();
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var firefoxProfilesPath = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");

            if (!Directory.Exists(firefoxProfilesPath)) return profiles;

            try
            {
                foreach (var profileDir in Directory.GetDirectories(firefoxProfilesPath))
                {
                    var profileName = Path.GetFileName(profileDir);
                    var extensions = ScanFirefoxExtensions(profileDir);

                    profiles.Add(new BrowserProfile
                    {
                        BrowserType = BrowserType.Firefox,
                        ProfileName = profileName,
                        ProfilePath = profileDir,
                        Extensions = extensions
                    });
                }
            }
            catch { }

            return profiles;
        }

        private static List<BrowserExtension> ScanFirefoxExtensions(string profileDir)
        {
            var extensions = new List<BrowserExtension>();
            var extensionsJsonPath = Path.Combine(profileDir, "extensions.json");

            if (!File.Exists(extensionsJsonPath)) return extensions;

            try
            {
                var json = File.ReadAllText(extensionsJsonPath);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("addons", out var addons) && addons.ValueKind == JsonValueKind.Array)
                {
                    foreach (var addon in addons.EnumerateArray())
                    {
                        string id = addon.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
                        string name = addon.TryGetProperty("defaultLocale", out var loc) && loc.TryGetProperty("name", out var nameProp) 
                            ? nameProp.GetString() ?? id : id;
                        string version = addon.TryGetProperty("version", out var v) ? v.GetString() ?? "1.0" : "1.0";
                        string description = loc.TryGetProperty("description", out var d) ? d.GetString() ?? string.Empty : string.Empty;
                        bool isEnabled = addon.TryGetProperty("active", out var active) && active.GetBoolean();
                        bool isSystem = addon.TryGetProperty("isSystemAddon", out var sys) && sys.GetBoolean();

                        if (isSystem) continue; // Skip built-in Firefox addons

                        extensions.Add(new BrowserExtension
                        {
                            Id = id,
                            Name = name,
                            Version = version,
                            Description = description,
                            IsEnabled = isEnabled,
                            IsSideloaded = false,
                            RiskLevel = RiskLevel.Clean
                        });
                    }
                }
            }
            catch { }

            return extensions;
        }
    }
}
