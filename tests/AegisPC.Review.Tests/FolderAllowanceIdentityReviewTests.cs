using System.IO;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Exercises identity on inert files in an isolated store; starts no watcher or enforcement.</summary>
public sealed class FolderAllowanceIdentityReviewTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "UltronAllowanceReview", Guid.NewGuid().ToString("N"));
    /// <summary>Creates a unique laboratory store without loading personal folder metadata.</summary>
    public FolderAllowanceIdentityReviewTests() => Directory.CreateDirectory(_root);

    /// <summary>Replaced bytes cannot inherit the original allowance, including after a store reload.</summary>
    [Fact]
    public void ChangedContentInvalidatesAllowanceAcrossReload()
    {
        string file = Path.Combine(_root, "program.bin");
        File.WriteAllText(file, "inert original content");
        var gate = new ProtectedFolderGate(storageDirectory: _root);
        Assert.Empty(gate.ProtectedDirectories);
        gate.AddAllowedApplication(file);
        Assert.True(gate.IsApplicationAllowed(file));
        Assert.Equal(64, Assert.Single(gate.AllowedApplications).SHA256!.Length);
        var reloaded = new ProtectedFolderGate(storageDirectory: _root);
        Assert.True(reloaded.IsApplicationAllowed(file));
        File.WriteAllText(file, "replacement with the same display name");
        Assert.False(gate.IsApplicationAllowed(file));
        Assert.False(reloaded.IsApplicationAllowed(file));
    }

    /// <summary>Legacy path-only records remain metadata but cannot grant permission.</summary>
    [Fact]
    public void LegacyPathOnlyEntryIsNotPermission()
    {
        string file = Path.Combine(_root, "legacy.bin");
        File.WriteAllText(file, "inert");
        File.WriteAllText(Path.Combine(_root, "allowed_ransomware_apps.json"),
            System.Text.Json.JsonSerializer.Serialize(new[] { new { ExecutablePath = file } }));
        var gate = new ProtectedFolderGate(storageDirectory: _root);
        Assert.Single(gate.AllowedApplications);
        Assert.False(gate.IsApplicationAllowed(file));
    }

    /// <summary>Deletion and rename cannot satisfy an earlier path/content identity.</summary>
    [Fact]
    public void DeletedOrRenamedFileIsNotAllowed()
    {
        string file = Path.Combine(_root, "original.bin");
        File.WriteAllText(file, "inert");
        var gate = new ProtectedFolderGate(storageDirectory: _root);
        gate.AddAllowedApplication(file);
        string renamed = Path.Combine(_root, "renamed.bin");
        File.Move(file, renamed);
        Assert.False(gate.IsApplicationAllowed(file));
        Assert.False(gate.IsApplicationAllowed(renamed));
    }

    /// <summary>Relative names and the product executable are not implicit exemptions.</summary>
    [Fact]
    public void ProductAndDisplayNameDoNotGrantPermission()
    {
        var gate = new ProtectedFolderGate(storageDirectory: _root);
        gate.AddAllowedApplication("display-name.exe");
        Assert.Empty(gate.AllowedApplications);
        Assert.False(gate.IsApplicationAllowed("display-name.exe"));
        Assert.False(gate.IsApplicationAllowed(Environment.ProcessPath!));
    }

    /// <summary>Path-segment boundaries reject similarly named sibling folders.</summary>
    [Fact]
    public void ProtectedMembershipRejectsSiblingPrefix()
    {
        string folder = Path.Combine(_root, "data");
        Directory.CreateDirectory(folder);
        var gate = new ProtectedFolderGate(storageDirectory: _root);
        gate.AddProtectedDirectory(folder);
        Assert.True(gate.IsPathInsideProtectedDirectory(Path.Combine(folder, "file.bin")));
        Assert.False(gate.IsPathInsideProtectedDirectory(Path.Combine(_root, "data-copy", "file.bin")));
    }

    /// <summary>Removes only the unique inert fixture root created by this instance.</summary>
    public void Dispose() => Directory.Delete(_root, recursive: true);
}
