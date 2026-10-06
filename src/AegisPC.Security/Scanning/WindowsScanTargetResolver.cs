using System.Security.Principal;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace AegisPC.Security.Scanning;

/// <summary>Read-only profile resolution through explicit Windows registrations, with injectable inert inventory routes.</summary>
public sealed class WindowsScanTargetResolver : IScanTargetResolver
{
    private const string ProfileList = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    private const string UserShellFolders = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
    private const string DownloadsId = "{374DE290-123F-4565-9164-39C4925E467B}";
    private readonly Func<bool> _systemContext;
    private readonly Func<ScanTargetResolution> _profileInventory;
    private readonly Func<ScanTargetResolution> _currentProfile;
    private readonly ILogger<WindowsScanTargetResolver>? _logger;

    /// <summary>Native readers are invoked only during ResolveAsync; injected routes require no Windows identity, registry or files.</summary>
    public WindowsScanTargetResolver(Func<bool>? systemContext = null,
        Func<ScanTargetResolution>? profileInventory = null, Func<ScanTargetResolution>? currentProfile = null,
        ILogger<WindowsScanTargetResolver>? logger = null)
    {
        _systemContext = systemContext ?? IsSystem;
        _profileInventory = profileInventory ?? ReadSystemProfiles;
        _currentProfile = currentProfile ?? ReadCurrentProfile;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task<ScanTargetResolution> ResolveAsync(CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var result = _systemContext() ? _profileInventory() : _currentProfile();
            cancellationToken.ThrowIfCancellationRequested();
            return Normalize(result);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception)
        {
            _logger?.LogWarning(exception, "User quick-scan target inventory is unavailable.");
            return new ScanTargetResolution([], [], false, ["UserProfileInventoryUnavailable"]);
        }
    }, cancellationToken);

    private static bool IsSystem()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows profile identity is unavailable.");
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem;
    }

    private ScanTargetResolution ReadSystemProfiles()
    {
        var profiles = new List<ScanProfileTarget>();
        var targets = new List<ScanDirectoryTarget>();
        var gaps = new List<string>();
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
            Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32);
        using var list = machine.OpenSubKey(ProfileList, writable: false);
        if (list == null) return new([], [], false, ["RegisteredProfileListUnavailable"]);
        string[] names = list.GetSubKeyNames();
        if (names.Length > 2048) gaps.Add("RegisteredProfileBudgetExceeded");
        foreach (string name in names.OrderBy(v => v, StringComparer.Ordinal).Take(2048))
        {
            try
            {
                var sid = new SecurityIdentifier(name);
                if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.LocalServiceSid) ||
                    sid.IsWellKnown(WellKnownSidType.NetworkServiceSid)) continue;
                using var profileKey = list.OpenSubKey(name, writable: false);
                string? rawPath = profileKey?.GetValue("ProfileImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                string path = ExpandProfilePath(rawPath);
                if (!IsFullPath(path)) { gaps.Add("RegisteredProfilePathUnavailable"); continue; }
                using var hive = Registry.Users.OpenSubKey(name, writable: false);
                var profile = new ScanProfileTarget { OwnerSid = sid.Value, ProfilePath = System.IO.Path.GetFullPath(path),
                    IsRegistryHiveLoaded = hive != null };
                profiles.Add(profile);
                AddProfileFolders(profile, hive, targets, gaps);
            }
            catch (Exception exception) when (exception is ArgumentException or System.Security.SecurityException or IOException or UnauthorizedAccessException)
            {
                gaps.Add("RegisteredProfileMetadataUnavailable");
                _logger?.LogWarning(exception, "A registered profile could not be resolved for quick scan.");
            }
        }
        if (profiles.Count == 0) gaps.Add("NoInteractiveProfileResolved");
        return new(profiles, targets, gaps.Count == 0, gaps);
    }

    private ScanTargetResolution ReadCurrentProfile()
    {
        if (!OperatingSystem.IsWindows()) return new([], [], false, ["WindowsUserProfileUnavailable"]);
        using var identity = WindowsIdentity.GetCurrent();
        string? sid = identity.User?.Value;
        string profilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(sid) || !IsFullPath(profilePath)) return new([], [], false, ["CurrentUserProfileUnavailable"]);
        var profile = new ScanProfileTarget { OwnerSid = sid, ProfilePath = System.IO.Path.GetFullPath(profilePath), IsRegistryHiveLoaded = true };
        using var hive = Registry.Users.OpenSubKey(sid, writable: false);
        var targets = new List<ScanDirectoryTarget>();
        var gaps = new List<string>();
        AddProfileFolders(profile with { IsRegistryHiveLoaded = hive != null }, hive, targets, gaps);
        // Current-user known folders are authoritative for Desktop/Startup/LocalAppData redirection.
        ReplaceCurrent(ScanDirectoryKind.Desktop, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
        ReplaceCurrent(ScanDirectoryKind.UserStartup, Environment.GetFolderPath(Environment.SpecialFolder.Startup));
        ReplaceCurrent(ScanDirectoryKind.Documents, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (IsFullPath(local)) ReplaceCurrent(ScanDirectoryKind.LocalTemp, System.IO.Path.Combine(local, "Temp"));
        return new([profile with { IsRegistryHiveLoaded = hive != null }], targets, gaps.Count == 0, gaps);

        void ReplaceCurrent(ScanDirectoryKind kind, string path)
        {
            if (!IsFullPath(path)) return;
            targets.RemoveAll(target => target.Kind == kind);
            targets.Add(new ScanDirectoryTarget { OwnerSid = sid, Kind = kind, Path = System.IO.Path.GetFullPath(path),
                Recursive = kind == ScanDirectoryKind.UserStartup });
        }
    }

    private void AddProfileFolders(ScanProfileTarget profile, RegistryKey? hive, List<ScanDirectoryTarget> targets, List<string> gaps)
    {
        if (!profile.IsRegistryHiveLoaded) gaps.Add("UserRegistryHiveNotLoaded");
        using var folders = hive?.OpenSubKey(UserShellFolders, writable: false);
        if (folders == null) gaps.Add("UserKnownFolderRedirectionUnavailable");
        string roaming = System.IO.Path.Combine(profile.ProfilePath, @"AppData\Roaming");
        string local = System.IO.Path.Combine(profile.ProfilePath, @"AppData\Local");
        roaming = ReadFolder("AppData", roaming);
        local = ReadFolder("Local AppData", local);
        Add(ScanDirectoryKind.Downloads, ReadFolder(DownloadsId, System.IO.Path.Combine(profile.ProfilePath, "Downloads")));
        Add(ScanDirectoryKind.Desktop, ReadFolder("Desktop", System.IO.Path.Combine(profile.ProfilePath, "Desktop")));
        Add(ScanDirectoryKind.Documents, ReadFolder("Personal", System.IO.Path.Combine(profile.ProfilePath, "Documents")));
        Add(ScanDirectoryKind.LocalTemp, System.IO.Path.Combine(local, "Temp"));
        Add(ScanDirectoryKind.UserStartup, ReadFolder("Startup",
            System.IO.Path.Combine(roaming, @"Microsoft\Windows\Start Menu\Programs\Startup")));

        string ReadFolder(string value, string fallback)
        {
            try
            {
                string? raw = folders?.GetValue(value, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                string expanded = ExpandUserPath(raw, profile.ProfilePath, local, roaming);
                if (IsFullPath(expanded)) return System.IO.Path.GetFullPath(expanded);
                gaps.Add("UserKnownFolderConventionalFallback");
            }
            catch (Exception exception) when (exception is ArgumentException or System.Security.SecurityException or IOException or UnauthorizedAccessException)
            {
                gaps.Add("UserKnownFolderMetadataUnavailable");
                _logger?.LogWarning(exception, "A user known-folder path could not be resolved.");
            }
            return fallback;
        }
        void Add(ScanDirectoryKind kind, string path) => targets.Add(new ScanDirectoryTarget
        { OwnerSid = profile.OwnerSid, Path = path, Kind = kind, Recursive = kind == ScanDirectoryKind.UserStartup });
    }

    private static ScanTargetResolution Normalize(ScanTargetResolution result)
    {
        var gaps = result.Limitations.ToList();
        bool LocalPath(string path) => IsFullPath(path) && AegisPC.Core.Helpers.ImplicitLocalPathPolicy.HasLocalSyntax(path);
        var profiles = result.Profiles.Where(profile => !string.IsNullOrWhiteSpace(profile.OwnerSid) && LocalPath(profile.ProfilePath)).ToArray();
        if (profiles.Length != result.Profiles.Count) gaps.Add("RegisteredProfileIdentityOrPathInvalid");
        if (profiles.Any(profile => !profile.IsRegistryHiveLoaded)) gaps.Add("UserRegistryHiveNotLoaded");
        var owners = profiles.Select(profile => profile.OwnerSid).ToHashSet(StringComparer.Ordinal);
        var targets = result.DirectoryTargets.Where(target => owners.Contains(target.OwnerSid) && LocalPath(target.Path))
            .DistinctBy(target => (target.OwnerSid, target.Kind, target.Path.ToUpperInvariant()))
            .OrderBy(target => target.OwnerSid, StringComparer.Ordinal).ThenBy(target => target.Kind).ToArray();
        if (targets.Length < result.DirectoryTargets.Count && result.DirectoryTargets.Any(target => !owners.Contains(target.OwnerSid) || !LocalPath(target.Path)))
            gaps.Add("UserScanTargetIdentityOrPathInvalid");
        if (result.DirectoryTargets.Any(target => !AegisPC.Core.Helpers.ImplicitLocalPathPolicy.HasLocalSyntax(target.Path)) ||
            result.Profiles.Any(profile => !AegisPC.Core.Helpers.ImplicitLocalPathPolicy.HasLocalSyntax(profile.ProfilePath)))
            gaps.Add("ImplicitNetworkOrDeviceTargetRequiresExplicitSelection");
        return new(profiles.OrderBy(profile => profile.OwnerSid, StringComparer.Ordinal), targets, result.IsComplete && gaps.Count == 0, gaps);
    }

    private static string ExpandProfilePath(string? path) => ExpandUserPath(path, null);
    private static string ExpandUserPath(string? path, string? profile, string? local = null, string? roaming = null)
    {
        string value = path?.Trim() ?? string.Empty;
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        value = value.Replace("%SystemRoot%", windows, StringComparison.OrdinalIgnoreCase)
            .Replace("%SystemDrive%", System.IO.Path.GetPathRoot(windows)?.TrimEnd('\\') ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        if (profile != null)
            value = value.Replace("%USERPROFILE%", profile, StringComparison.OrdinalIgnoreCase)
                .Replace("%LOCALAPPDATA%", local ?? System.IO.Path.Combine(profile, @"AppData\Local"), StringComparison.OrdinalIgnoreCase)
                .Replace("%APPDATA%", roaming ?? System.IO.Path.Combine(profile, @"AppData\Roaming"), StringComparison.OrdinalIgnoreCase);
        return value;
    }

    private static bool IsFullPath(string value)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(value) || value.Contains('%') || !System.IO.Path.IsPathFullyQualified(value)) return false;
            _ = System.IO.Path.GetFullPath(value); // Reject invalid path characters, not just a syntactically qualified prefix.
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException) { return false; }
    }
}
