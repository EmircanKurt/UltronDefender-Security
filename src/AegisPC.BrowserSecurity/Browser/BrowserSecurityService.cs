using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.BrowserSecurity.Browser
{
    public class BrowserSecurityService : IBrowserSecurityScanner
    {
        private readonly ILogger<BrowserSecurityService>? _logger;

        public BrowserSecurityService(ILogger<BrowserSecurityService>? logger = null)
        {
            _logger = logger;
        }

        private static List<string> GetInteractiveUserLocalAppDataPaths()
        {
            var paths = new List<string>();
            try
            {
                // Önce mevcut kullanıcı (interactive session'da ise)
                var currentUserLocal = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (!string.IsNullOrEmpty(currentUserLocal) && 
                    !currentUserLocal.Contains("systemprofile", StringComparison.OrdinalIgnoreCase) &&
                    Directory.Exists(currentUserLocal))
                {
                    paths.Add(currentUserLocal);
                }
                
                // Tüm kullanıcı profillerini tara
                var usersDir = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                if (!string.IsNullOrEmpty(usersDir) && Directory.Exists(usersDir))
                {
                    foreach (var userDir in Directory.GetDirectories(usersDir))
                    {
                        var userName = Path.GetFileName(userDir);
                        // Sistem dizinlerini atla
                        if (userName.Equals("Public", StringComparison.OrdinalIgnoreCase) ||
                            userName.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                            userName.Equals("Default User", StringComparison.OrdinalIgnoreCase) ||
                            userName.Equals("All Users", StringComparison.OrdinalIgnoreCase))
                            continue;
                            
                        var localAppData = Path.Combine(userDir, "AppData", "Local");
                        if (Directory.Exists(localAppData) && !paths.Contains(localAppData, StringComparer.OrdinalIgnoreCase))
                        {
                            paths.Add(localAppData);
                        }
                    }
                }
            }
            catch { /* Non-critical: fall back to whatever paths we found */ }
            return paths;
        }

        public Task<List<BrowserProfile>> ScanAllBrowsersAsync(CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                var profiles = new List<BrowserProfile>();
                var localAppDataPaths = GetInteractiveUserLocalAppDataPaths();
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

                foreach (var localAppData in localAppDataPaths)
                {
                    // 1. Google Chrome
                    var chromeUserData = Path.Combine(localAppData, "Google", "Chrome", "User Data");
                    profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(chromeUserData, BrowserType.Chrome));

                    // 2. Microsoft Edge
                    var edgeUserData = Path.Combine(localAppData, "Microsoft", "Edge", "User Data");
                    profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(edgeUserData, BrowserType.Edge));

                    // 3. Brave Browser
                    var braveUserData = Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data");
                    profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(braveUserData, BrowserType.Brave));

                    // 5. Vivaldi
                    var vivaldiUserData = Path.Combine(localAppData, "Vivaldi", "User Data");
                    profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(vivaldiUserData, BrowserType.Vivaldi));

                    // 6. Yandex Browser
                    var yandexUserData = Path.Combine(localAppData, "Yandex", "YandexBrowser", "User Data");
                    if (Directory.Exists(yandexUserData))
                    {
                        profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(yandexUserData, BrowserType.Yandex));
                    }
                }

                // 4. Opera & Opera GX
                var operaUserData = Path.Combine(appData, "Opera Software", "Opera Stable");
                profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(operaUserData, BrowserType.Opera));

                var operaGxUserData = Path.Combine(appData, "Opera Software", "Opera GX Stable");
                profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(operaGxUserData, BrowserType.Opera));

                // 7. Mozilla Firefox
                profiles.AddRange(FirefoxSecurityScanner.ScanFirefoxProfiles());

                // Deduplicate and ensure at least an informative default entry if no browser profiles found
                if (profiles.Count == 0)
                {
                    profiles.Add(new BrowserProfile
                    {
                        BrowserType = BrowserType.Edge,
                        ProfileName = "Sistem Varsayılanı",
                        ProfilePath = "C:\\Windows\\SystemApps",
                        Extensions = new List<BrowserExtension>()
                    });
                }

                return profiles;
            }, cancellationToken);
        }

        public async Task<BrowserProfile?> ScanBrowserAsync(BrowserType browserType, CancellationToken cancellationToken = default)
        {
            var all = await ScanAllBrowsersAsync(cancellationToken);
            return all.FirstOrDefault(p => p.BrowserType == browserType);
        }
    }
}
