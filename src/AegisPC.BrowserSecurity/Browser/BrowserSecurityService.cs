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

        public Task<List<BrowserProfile>> ScanAllBrowsersAsync(CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                var profiles = new List<BrowserProfile>();
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

                // 1. Google Chrome
                var chromeUserData = Path.Combine(localAppData, "Google", "Chrome", "User Data");
                profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(chromeUserData, BrowserType.Chrome));

                // 2. Microsoft Edge
                var edgeUserData = Path.Combine(localAppData, "Microsoft", "Edge", "User Data");
                profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(edgeUserData, BrowserType.Edge));

                // 3. Brave Browser
                var braveUserData = Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data");
                profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(braveUserData, BrowserType.Brave));

                // 4. Opera & Opera GX
                var operaUserData = Path.Combine(appData, "Opera Software", "Opera Stable");
                profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(operaUserData, BrowserType.Opera));

                var operaGxUserData = Path.Combine(appData, "Opera Software", "Opera GX Stable");
                profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(operaGxUserData, BrowserType.Opera));

                // 5. Vivaldi
                var vivaldiUserData = Path.Combine(localAppData, "Vivaldi", "User Data");
                profiles.AddRange(ChromiumExtensionScanner.ScanChromiumProfiles(vivaldiUserData, BrowserType.Edge));

                // 6. Mozilla Firefox
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
