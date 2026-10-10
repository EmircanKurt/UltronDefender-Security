using System.Diagnostics;
using AegisPC.Core.Enums;

namespace AegisPC.BrowserSecurity.Browser;

/// <summary>Resolves only the interactive process user's conventional browser roots; it never enumerates other users.</summary>
public sealed class CurrentUserBrowserProfileResolver : IBrowserProfileResolver
{
    /// <summary>Returns current-user roots or none in session zero; a service must inject separately authorized profile roots.</summary>
    public IReadOnlyList<BrowserProfileRoot> ResolveRoots()
    {
        if (!OperatingSystem.IsWindows()) return Array.Empty<BrowserProfileRoot>();
        try
        {
            using var process = Process.GetCurrentProcess();
            if (process.SessionId == 0) return Array.Empty<BrowserProfileRoot>();
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (string.IsNullOrWhiteSpace(local) || string.IsNullOrWhiteSpace(roaming)) return Array.Empty<BrowserProfileRoot>();
            return new[]
            {
                Root(BrowserType.Chrome, local, "Google", "Chrome", "User Data"),
                Root(BrowserType.Edge, local, "Microsoft", "Edge", "User Data"),
                Root(BrowserType.Brave, local, "BraveSoftware", "Brave-Browser", "User Data"),
                Root(BrowserType.Vivaldi, local, "Vivaldi", "User Data"),
                Root(BrowserType.Yandex, local, "Yandex", "YandexBrowser", "User Data"),
                Root(BrowserType.Opera, roaming, "Opera Software", "Opera Stable"),
                Root(BrowserType.Opera, roaming, "Opera Software", "Opera GX Stable"),
                Root(BrowserType.Firefox, roaming, "Mozilla", "Firefox", "Profiles")
            };
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        { Trace.WriteLine($"Browser Defender current-user resolution failed: {ex.GetType().Name}."); return Array.Empty<BrowserProfileRoot>(); }
    }

    private static BrowserProfileRoot Root(BrowserType browser, params string[] segments) =>
        new() { BrowserType = browser, RootPath = Path.Combine(segments) };
}
