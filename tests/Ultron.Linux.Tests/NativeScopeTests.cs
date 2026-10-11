using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Ultron.PortableInspection;
using Xunit;

namespace Ultron.Linux.Tests;

/// <summary>Marks native Linux scenarios explicitly; Windows execution cannot stand in for Linux validation.</summary>
public sealed class LinuxFactAttribute : FactAttribute
{
    /// <summary>Skips native scenarios on other operating systems with an explicit evidence limitation.</summary>
    public LinuxFactAttribute() { if (!OperatingSystem.IsLinux()) Skip = "Native Linux scenario requires an actual Linux runner."; }
}

/// <summary>Uses inert real disk files and native special nodes to verify read-only scope boundaries on Linux.</summary>
public sealed class NativeScopeTests
{
    /// <summary>Verifies a normal selected file gets the hash of its complete bounded immutable snapshot.</summary>
    [LinuxFact]
    public async Task RegularFileIsReadWithoutModification()
    {
        using var fixture = new FixtureDirectory();
        string file = fixture.File("ordinary.txt", "Inert native Linux fixture.");
        byte[] original = File.ReadAllBytes(file);
        var report = Assert.Single(await new ManualScopeScanner(new()).ScanAsync(file, new()));
        Assert.Equal(Convert.ToHexString(SHA256.HashData(original)), report.Sha256);
        Assert.Equal(original, File.ReadAllBytes(file));
        Assert.NotEqual("Clean", report.Status);
    }

    /// <summary>Verifies direct symbolic links remain incomplete and their target content is never hashed.</summary>
    [LinuxFact]
    public async Task FileSymbolicLinkIsNotRead()
    {
        using var fixture = new FixtureDirectory();
        string target = fixture.File("target", "Ordinary target bytes.");
        string link = Path.Combine(fixture.Path, "link");
        File.CreateSymbolicLink(link, target);
        var report = Assert.Single(await new ManualScopeScanner(new()).ScanAsync(link, new()));
        Assert.Empty(report.Sha256);
        Assert.False(report.ChecksComplete);
        Assert.Contains(report.Limitations, gap => gap.Contains("Non-regular", StringComparison.Ordinal));
    }

    /// <summary>Verifies a symbolic directory in any ancestor cannot redirect a selected path.</summary>
    [LinuxFact]
    public async Task AncestorSymbolicLinkIsNotFollowed()
    {
        using var fixture = new FixtureDirectory();
        string target = Directory.CreateDirectory(Path.Combine(fixture.Path, "target")).FullName;
        File.WriteAllText(Path.Combine(target, "file"), "Ordinary bytes.");
        string link = Path.Combine(fixture.Path, "link");
        Directory.CreateSymbolicLink(link, target);
        var report = Assert.Single(await new ManualScopeScanner(new()).ScanAsync(Path.Combine(link, "file"), new()));
        Assert.Empty(report.Sha256);
        Assert.False(report.ChecksComplete);
    }

    /// <summary>Verifies a FIFO is rejected without opening it for content or waiting for a writer.</summary>
    [LinuxFact]
    public async Task FifoIsRejectedWithoutBlocking()
    {
        using var fixture = new FixtureDirectory();
        string fifo = Path.Combine(fixture.Path, "fifo");
        if (MakeFifo(fifo, 0x180) != 0) throw new IOException(new Win32Exception(Marshal.GetLastPInvokeError()).Message);
        var reports = await new ManualScopeScanner(new()).ScanAsync(fifo, new()).WaitAsync(TimeSpan.FromSeconds(5));
        var report = Assert.Single(reports);
        Assert.Empty(report.Sha256);
        Assert.False(report.ChecksComplete);
        Assert.Contains(report.Limitations, gap => gap.Contains("Non-regular", StringComparison.Ordinal));
    }

    /// <summary>Verifies the actual OS null device is reported unsupported without reading its content.</summary>
    [LinuxFact]
    public async Task DeviceIsRejected()
    {
        var report = Assert.Single(await new ManualScopeScanner(new()).ScanAsync("/dev/null", new()));
        Assert.Empty(report.Sha256);
        Assert.False(report.ChecksComplete);
    }

    /// <summary>Verifies a source changed during an admission pause cannot retain stale snapshot metadata.</summary>
    [LinuxFact]
    public async Task ChangedSourceIsDiscarded()
    {
        using var fixture = new FixtureDirectory();
        string file = fixture.File("changing", "Before.");
        var control = new ScanControl();
        control.Pause();
        var scan = new ManualScopeScanner(new()).ScanAsync(file, control);
        File.WriteAllText(file, "After: changed length and bytes.");
        control.Resume();
        var report = Assert.Single(await scan);
        Assert.Empty(report.Sha256);
        Assert.Contains(report.Limitations, gap => gap.Contains("changed", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Verifies path limits are visible and unvisited files do not become successful results.</summary>
    [LinuxFact]
    public async Task FolderPathBudgetReportsOmittedScope()
    {
        using var fixture = new FixtureDirectory();
        fixture.File("first", "Ordinary."); fixture.File("second", "Ordinary.");
        var reports = await new ManualScopeScanner(new(), new() { MaximumPaths = 1 }).ScanAsync(fixture.Path, new());
        Assert.Contains(reports, report => report.Limitations.Any(gap => gap.Contains("budget", StringComparison.OrdinalIgnoreCase)));
        Assert.All(reports, report => Assert.False(report.ChecksComplete));
    }

    /// <summary>Verifies directory entry access failures consume the same path budget as successfully opened nodes.</summary>
    [LinuxFact]
    public async Task InaccessibleEntriesCannotBypassPathBudget()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Native fixture requires Linux.");
        using var fixture = new FixtureDirectory();
        string folder = Directory.CreateDirectory(Path.Combine(fixture.Path, "unsearchable")).FullName;
        for (int index = 0; index < 20; index++) File.WriteAllText(Path.Combine(folder, $"entry-{index}"), "Inert.");
        File.SetUnixFileMode(folder, UnixFileMode.UserRead);
        try
        {
            var reports = await new ManualScopeScanner(new(), new() { MaximumPaths = 3 }).ScanAsync(folder, new());
            Assert.True(reports.Count <= 3, "Access failure reports must remain within the configured visited path budget plus its terminal coverage report.");
            Assert.Contains(reports, report => report.Limitations.Any(gap => gap.Contains("budget", StringComparison.OrdinalIgnoreCase)));
            Assert.All(reports, report => Assert.Empty(report.Sha256));
        }
        finally { File.SetUnixFileMode(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
    }

    /// <summary>Verifies a procfs regular node with declared size zero cannot publish the hash of an unread nonempty source.</summary>
    [LinuxFact]
    public async Task SizeZeroVirtualSourceDoesNotPublishEmptyHash()
    {
        Assert.Equal(0, new FileInfo("/proc/version").Length);
        Assert.NotEmpty(File.ReadAllBytes("/proc/version"));
        var report = Assert.Single(await new ManualScopeScanner(new()).ScanAsync("/proc/version", new()));
        Assert.Empty(report.Sha256);
        Assert.False(report.ChecksComplete);
        Assert.Contains(report.Limitations, gap => gap.Contains("beyond its declared size", StringComparison.Ordinal));
    }

    /// <summary>Verifies an ordinary empty disk file still receives its actual complete-snapshot hash after EOF verification.</summary>
    [LinuxFact]
    public async Task OrdinaryEmptyFileHasItsActualSnapshotHash()
    {
        using var fixture = new FixtureDirectory();
        string file = fixture.File("empty", string.Empty);
        var report = Assert.Single(await new ManualScopeScanner(new()).ScanAsync(file, new()));
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Array.Empty<byte>())), report.Sha256);
        Assert.DoesNotContain(report.Limitations, gap => gap.Contains("beyond its declared size", StringComparison.Ordinal));
    }

    [DllImport("libc", EntryPoint = "mkfifo", SetLastError = true)]
    private static extern int MakeFifo([MarshalAs(UnmanagedType.LPUTF8Str)] string path, uint mode);

    private sealed class FixtureDirectory : IDisposable
    {
        internal string Path { get; } = Directory.CreateTempSubdirectory("ultron-linux-inert-").FullName;
        internal string File(string name, string content)
        {
            string target = System.IO.Path.Combine(Path, name);
            System.IO.File.WriteAllText(target, content);
            return target;
        }
        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
