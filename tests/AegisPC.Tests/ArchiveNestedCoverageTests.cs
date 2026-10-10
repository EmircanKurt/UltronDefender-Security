using System;
using System.Collections.Concurrent;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Checks bounded nested ZIP coverage and preservation of findings from incomplete scans.</summary>
[Collection("SequentialDiskTests")]
public sealed class ArchiveNestedCoverageTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "Ultron_ArchiveNested_" + Guid.NewGuid().ToString("N"));

    /// <summary>Creates an isolated benign fixture directory for each test instance.</summary>
    public ArchiveNestedCoverageTests() => Directory.CreateDirectory(_root);

    /// <summary>Removes only this test instance's temporary fixture directory.</summary>
    public void Dispose() => Directory.Delete(_root, recursive: true);

    /// <summary>Even inspected benign nested members must not imply full archive coverage.</summary>
    [Fact]
    public async Task NestedZipWithBenignMember_InspectsButKeepsCoveragePartial()
    {
        string path = await CreateNestedArchiveAsync("outer.zip", "inner.txt", "notes.txt", "BENIGN NESTED DOCUMENT");
        var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
        Assert.True(result.IsArchive);
        Assert.False(result.IsComplete);
        Assert.Equal(2, result.TotalEntries);
        Assert.Empty(result.Findings);
        Assert.Contains("kısmi", result.CoverageLimitation ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Content-only nested evidence is preserved without upgrading incomplete coverage to success.</summary>
    [Fact]
    public async Task NestedZipWithContentPattern_RetainsFindingAndPartialCoverage()
    {
        string path = await CreateNestedArchiveAsync("outer.jar", "renamed.txt", "notes.txt",
            "Educational reference: amsiInitFailed");
        var archiveResult = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
        Assert.False(archiveResult.IsComplete);
        var finding = Assert.Single(archiveResult.Findings);
        Assert.Equal(RiskLevel.Suspicious, finding.RiskLevel);
        Assert.Contains("renamed.txt -> notes.txt", finding.ObjectPath);

        var hash = new HashService();
        var scanner = new FileScannerService(hash, new SignatureVerifier(), new RiskScoringEngine(),
            new AllowlistService(hash));
        var detailed = await scanner.ScanFileDetailedAsync(path, TimeSpan.FromSeconds(10));
        Assert.Equal(FileScanOutcome.Failed, detailed.Outcome);
        Assert.NotNull(detailed.Finding);
        Assert.False(detailed.IsFromCache);
        Assert.Contains("kısmi", detailed.ErrorMessage ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A member filename alone cannot cause an incomplete security decision.</summary>
    [Fact]
    public async Task BenignMemberNamedZip_DoesNotCreateFilenameBasedPartialCoverage()
    {
        string path = Path.Combine(_root, "plain.zip");
        using (var outer = ZipFile.Open(path, ZipArchiveMode.Create))
        using (var writer = new StreamWriter(outer.CreateEntry("not_an_archive.jar").Open()))
            await writer.WriteAsync("BENIGN PLAIN TEXT");
        var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
        Assert.True(result.IsComplete);
        Assert.Empty(result.Findings);
    }

    /// <summary>The nested-entry quota prevents unbounded work and reports omitted members.</summary>
    [Fact]
    public async Task NestedEntryBudget_StopsAtBoundAndDoesNotCallRemainderClean()
    {
        using var nested = new MemoryStream();
        using (var inner = new ZipArchive(nested, ZipArchiveMode.Create, leaveOpen: true))
            for (int index = 0; index < 257; index++)
                inner.CreateEntry($"benign-{index}.txt");
        string path = Path.Combine(_root, "many.jar");
        using (var outer = ZipFile.Open(path, ZipArchiveMode.Create))
        using (var output = outer.CreateEntry("inner.bin").Open())
            await output.WriteAsync(nested.ToArray());
        var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
        Assert.False(result.IsComplete);
        Assert.Contains("üye sayısı bütçesi", result.CoverageLimitation ?? string.Empty);
        Assert.Empty(result.Findings);
    }

    /// <summary>The failure counter represents incomplete coverage while retaining any confirmed evidence.</summary>
    [Fact]
    public async Task FailedInspectionWithFinding_CountsIncompleteAndPreservesEvidence()
    {
        string path = Path.Combine(_root, "fixture.zip");
        await File.WriteAllTextAsync(path, "BENIGN FIXTURE");
        var evidence = new SecurityFinding { ObjectPath = path, RiskLevel = RiskLevel.Suspicious, RiskScore = 40 };
        var findings = new ConcurrentBag<SecurityFinding>();
        using var queue = new ScanQueueCoordinator();
        var counts = await queue.ExecuteScanQueueDetailedAsync(path, ScanType.Custom,
            async enqueue => await enqueue(path),
            (file, _) => Task.FromResult(FileScanDetailedResult.CreateFailed(file,
                "Arşiv incelemesi kısmi kaldı.", TimeSpan.Zero, evidence)),
            findings, (_, _, _, _, _, _) => { }, CancellationToken.None);
        Assert.Equal(1, counts.FailedFiles);
        Assert.Same(evidence, Assert.Single(findings));
    }

    private async Task<string> CreateNestedArchiveAsync(string outerName, string innerName,
        string memberName, string content)
    {
        using var nested = new MemoryStream();
        using (var inner = new ZipArchive(nested, ZipArchiveMode.Create, leaveOpen: true))
        using (var writer = new StreamWriter(inner.CreateEntry(memberName).Open(), Encoding.UTF8))
            await writer.WriteAsync(content);
        string path = Path.Combine(_root, outerName);
        using (var outer = ZipFile.Open(path, ZipArchiveMode.Create))
        using (var output = outer.CreateEntry(innerName).Open())
            await output.WriteAsync(nested.ToArray());
        return path;
    }
}
