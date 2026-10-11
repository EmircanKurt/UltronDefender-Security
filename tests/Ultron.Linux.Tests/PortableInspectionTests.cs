using System.IO.Compression;
using System.Text;
using Ultron.PortableInspection;
using Xunit;

namespace Ultron.Linux.Tests;

/// <summary>Exercises inert content fixtures and verifies conservative preview coverage decisions.</summary>
public sealed class PortableInspectionTests
{
    /// <summary>Verifies the same text is routed identically after an extension change and is never certified clean.</summary>
    [Fact]
    public async Task RenamedTextRetainsContentIdentity()
    {
        var inspector = new PreviewInspector();
        byte[] bytes = Encoding.UTF8.GetBytes("An ordinary inert document.\n");
        var text = await inspector.InspectAsync("document.txt", bytes);
        var renamed = await inspector.InspectAsync("document.exe", bytes);
        Assert.Contains("Text", text.Formats);
        Assert.Equal(text.Formats, renamed.Formats);
        Assert.Equal(text.Sha256, renamed.Sha256);
        Assert.NotEqual("Clean", renamed.Status);
        Assert.Empty(renamed.ReviewIndicators);
    }

    /// <summary>Ensures a size budget cannot publish a complete or hashed inspection of unexamined content.</summary>
    [Fact]
    public async Task OversizedSnapshotIsUnknown()
    {
        var report = await new PreviewInspector().InspectAsync("large", new byte[33], new() { MaximumFileBytes = 32 });
        Assert.False(report.ChecksComplete);
        Assert.Empty(report.Sha256);
        Assert.Contains(report.Limitations, x => x.Contains("budget", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Checks malformed PE bytes remain a structural candidate with explicit unavailable deep coverage.</summary>
    [Fact]
    public async Task PeCandidateCannotBeComplete()
    {
        var report = await new PreviewInspector().InspectAsync("renamed.dat", "MZinert truncated header"u8.ToArray());
        Assert.Contains("PortableExecutable", report.Formats);
        Assert.False(report.ChecksComplete);
        Assert.Contains(report.Limitations, x => x.Contains("PE", StringComparison.Ordinal));
        Assert.Empty(report.ReviewIndicators);
    }

    /// <summary>Verifies ZIP identification and member inspection use content while never extracting members to disk.</summary>
    [Fact]
    public async Task RenamedZipInspectsInertMember()
    {
        byte[] bytes = CreateZip("member.txt", "Ordinary member text.");
        var report = await new PreviewInspector().InspectAsync("archive.dat", bytes);
        Assert.Contains("Zip", report.Formats);
        var member = Assert.Single(report.Members);
        Assert.Contains("Text", member.Formats);
        Assert.NotEmpty(member.Sha256);
        Assert.Empty(member.ReviewIndicators);
    }

    /// <summary>Ensures expansion and entry limits survive a ZIP input and stay visible in the outer report.</summary>
    [Fact]
    public async Task ZipExpansionBudgetIsIncomplete()
    {
        var report = await new PreviewInspector().InspectAsync("zip", CreateZip("member", new string('A', 100)), new() { MaximumExpandedBytes = 50 });
        Assert.False(report.ChecksComplete);
        Assert.Contains(report.Limitations, x => x.Contains("budget", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Ensures unknown binary input cannot inherit successful coverage from an empty rule result.</summary>
    [Fact]
    public async Task UnknownBinaryRemainsUnknown()
    {
        var report = await new PreviewInspector().InspectAsync("blob", [0xff, 0, 0x81, 0, 0x80]);
        Assert.False(report.ChecksComplete);
        Assert.Equal("Unknown / incomplete", report.Status);
    }

    /// <summary>Checks cancellation propagates before parsing input rather than returning an unmatched status.</summary>
    [Fact]
    public async Task CancellationPropagates()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new PreviewInspector().InspectAsync("fixture", [1], cancellationToken: cancellation.Token));
    }

    /// <summary>Verifies callers cannot remove any hard resource cap or create invalid negative/zero budgets.</summary>
    [Fact]
    public async Task InvalidLimitsAreRejectedBeforeSourceAccess()
    {
        InspectionLimits[] invalid =
        [
            new() { MaximumFileBytes = -1 }, new() { MaximumFileBytes = 0 }, new() { MaximumFileBytes = 16 * 1024 * 1024 + 1 },
            new() { MaximumArchiveEntries = -1 }, new() { MaximumArchiveEntries = 0 }, new() { MaximumArchiveEntries = 129 },
            new() { MaximumExpandedBytes = -1 }, new() { MaximumExpandedBytes = 0 }, new() { MaximumExpandedBytes = 32 * 1024 * 1024 + 1 },
            new() { MaximumPaths = -1 }, new() { MaximumPaths = 0 }, new() { MaximumPaths = 5001 }
        ];
        foreach (var limits in invalid)
        {
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => new PreviewInspector().InspectAsync("inert", [1], limits));
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => new ManualScopeScanner(new(), limits).ScanAsync("not-opened", new()));
        }
    }

    private static byte[] CreateZip(string name, string content)
    {
        using var bytes = new MemoryStream();
        using (var zip = new ZipArchive(bytes, ZipArchiveMode.Create, true))
        using (var writer = new StreamWriter(zip.CreateEntry(name).Open())) writer.Write(content);
        return bytes.ToArray();
    }
}
