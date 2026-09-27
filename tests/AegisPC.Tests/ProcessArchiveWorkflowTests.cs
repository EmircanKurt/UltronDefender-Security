using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.App.ViewModels;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Contracts.Detection;
using AegisPC.Performance.Process;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.YaraEngine;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Tests;

/// <summary>Uses inert archive bytes and identity rejection only; never kills or suspends a host process.</summary>
[Collection("SequentialDiskTests")]
public sealed class ProcessArchiveWorkflowTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "Ultron_ProcessArchive_" + Guid.NewGuid().ToString("N"));
    private readonly ITestOutputHelper _output;
    public ProcessArchiveWorkflowTests(ITestOutputHelper output)
    {
        _output = output;
        Directory.CreateDirectory(_root);
    }
    public void Dispose() => Directory.Delete(_root, true);

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(-1)]
    public async Task PidOnlyTermination_RejectsSystemPidBeforeOpeningIt(int pid)
    {
        var result = await new ProcessTerminationService().TerminateProcessAsync(pid);
        Assert.False(result.Success);
        Assert.True(result.IsProtectedProcess);
    }

    [Fact]
    public async Task SelectedTermination_MissingSnapshotIdentityFailsClosed()
    {
        var method = typeof(ProcessTerminationService).GetMethod("TerminateSelectedProcessAsync");
        Assert.NotNull(method);
        var result = await (Task<ProcessTerminationResult>)method!.Invoke(new ProcessTerminationService(),
            new object[] { new ProcessInfo { PID = int.MaxValue, Name = "benign", ExecutablePath = "C:\\Fixture\\benign.exe" }, false, CancellationToken.None })!;
        Assert.False(result.Success);
        Assert.Contains("doğrulan", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UserWorkflow_DoesNotCallPidOnlyTermination()
    {
        string projectRoot = FindProjectRoot();
        string source = File.ReadAllText(Path.Combine(projectRoot, "src", "AegisPC.App", "ViewModels", "ProcessListViewModel.cs"));
        Assert.DoesNotContain("TerminateProcessAsync(target.PID", source);
        Assert.Contains("TerminateSelectedProcessAsync(target", source);
    }

    [Theory]
    [InlineData("svchost")]
    [InlineData("MsMpEng.exe")]
    public void WindowsServiceFilter_DoesNotHideUnsignedUserProcessByName(string name)
    {
        Assert.False(ProcessListViewModel.IsWindowsServiceOrSystem(new ProcessInfo
        {
            PID = 12345, Name = name, SessionId = 1,
            ExecutablePath = "C:\\Users\\Fixture\\Downloads\\" + name, IsSigned = false
        }));
    }

    [Fact]
    public void WindowsServiceFilter_DoesNotTrustLookalikeWindowsDirectory()
    {
        Assert.False(ProcessListViewModel.IsWindowsServiceOrSystem(new ProcessInfo
        {
            PID = 12345, Name = "benign", SessionId = 1, IsSigned = true,
            Publisher = "Microsoft Windows Publisher",
            ExecutablePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "-fixture", "System32", "benign.exe")
        }));
    }

    [Theory]
    [InlineData("minecraft-mod.jar", "com/example/Fixture.class")]
    [InlineData("renamed-mod.jpg", "asset.txt")]
    public async Task JarMembers_ReachConfiguredYaraWithoutExtractingToDisk(string archiveName, string memberName)
    {
        byte[] member = Encoding.UTF8.GetBytes(new string(' ', 20000) + "BENIGN ARCHIVE RULE REVIEW MARKER");
        var yara = new RecordingYaraEngine();
        var constructor = typeof(ArchiveSafetyScanner).GetConstructor(new[] { typeof(ILogger<ArchiveSafetyScanner>), typeof(IYaraEngine) });
        Assert.NotNull(constructor);
        var scanner = (ArchiveSafetyScanner)constructor!.Invoke(new object?[] { null, yara });
        string path = await CreateArchiveAsync(archiveName, memberName, member);
        var result = await scanner.ScanArchiveAsync(path);
        Assert.True(result.IsArchive);
        Assert.True(result.IsComplete);
        Assert.Equal(member, Assert.Single(yara.Buffers));
        var finding = Assert.Single(result.Findings);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(member)), finding.SHA256);
        Assert.Equal(FindingCategory.MalwareSuspicion, finding.Category);
        Assert.NotEqual(RiskLevel.ConfirmedMalicious, finding.RiskLevel);
        Assert.InRange(finding.RiskScore, 1, 75);
        Assert.Single(Directory.GetFiles(_root));
    }

    [Fact]
    public async Task JarMember_YaraFailureCannotProduceCompleteCleanCoverage()
    {
        var constructor = typeof(ArchiveSafetyScanner).GetConstructor(new[] { typeof(ILogger<ArchiveSafetyScanner>), typeof(IYaraEngine) });
        Assert.NotNull(constructor);
        var scanner = (ArchiveSafetyScanner)constructor!.Invoke(new object?[] { null, new RecordingYaraEngine { Throw = true } });
        string path = await CreateArchiveAsync("fixture.jar", "Fixture.class", Encoding.UTF8.GetBytes("BENIGN"));
        var result = await scanner.ScanArchiveAsync(path);
        Assert.False(result.IsComplete);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task JarGenericCommandReference_IsNotConfirmedMalware()
    {
        string path = await CreateArchiveAsync("fixture.jar", "Fixture.class", Encoding.UTF8.GetBytes("Educational reference: amsiInitFailed"));
        var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
        var finding = Assert.Single(result.Findings);
        Assert.Equal(FindingCategory.SuspiciousScript, finding.Category);
        Assert.NotEqual(RiskLevel.ConfirmedMalicious, finding.RiskLevel);
    }

    [Fact]
    public async Task JarMemberHash_IsComputedFromDecompressedBytesNotOuterArchive()
    {
        byte[] member = Encoding.UTF8.GetBytes("BENIGN HASH PIPELINE FIXTURE " + Guid.NewGuid().ToString("N"));
        string hash = Convert.ToHexString(SHA256.HashData(member));
        var field = typeof(MalwareSignatureDatabase).GetField("KnownThreatHashes", BindingFlags.NonPublic | BindingFlags.Static)!;
        var signatures = (Dictionary<string, (string Name, string Category, int Severity, string FirstSeen)>)field.GetValue(null)!;
        // This temporary in-memory entry is explicitly test data, never imported into production threat intelligence.
        signatures.Add(hash, ("Benign.TestOnly.HashPipeline", "TestFixture", 95, "test-only"));
        try
        {
            string path = await CreateArchiveAsync("fixture.jar", "Fixture.class", member);
            var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
            var finding = Assert.Single(result.Findings);
            Assert.Equal(hash, finding.SHA256);
            Assert.Equal(FindingCategory.KnownMalwareHash, finding.Category);
            Assert.Equal(RiskLevel.ConfirmedMalicious, finding.RiskLevel);
        }
        finally { signatures.Remove(hash); }
    }

    [Fact]
    public async Task JarMember_RealManagedRuleEngineInspectsBenignMarker()
    {
        string rules = Path.Combine(_root, "rules");
        Directory.CreateDirectory(rules);
        await File.WriteAllTextAsync(Path.Combine(rules, "fixture.yar"),
            "rule BenignJarReviewFixture { meta: description = \"Inert unit fixture, not malware intelligence\" severity = 95 strings: $marker = \"BENIGN JAR REVIEW UNIQUE MARKER\" condition: $marker }");
        var yara = new AegisPC.Security.Detection.YaraEngine.YaraEngine(rules);
        var constructor = typeof(ArchiveSafetyScanner).GetConstructor(new[] { typeof(ILogger<ArchiveSafetyScanner>), typeof(IYaraEngine) });
        Assert.NotNull(constructor);
        var scanner = (ArchiveSafetyScanner)constructor!.Invoke(new object?[] { null, yara });
        byte[] member = Encoding.UTF8.GetBytes("BENIGN JAR REVIEW UNIQUE MARKER");
        string path = await CreateArchiveAsync("fixture.jar", "Fixture.class", member);
        var result = await scanner.ScanArchiveAsync(path);
        var finding = Assert.Single(result.Findings);
        Assert.Contains("BenignJarReviewFixture", finding.Title);
        Assert.Equal(FindingCategory.MalwareSuspicion, finding.Category);
        Assert.NotEqual(RiskLevel.ConfirmedMalicious, finding.RiskLevel);
    }

    [Theory]
    [InlineData("shared-mod.jar")]
    [InlineData("shared-mod.jpg")]
    public async Task SharedDetectionHub_InspectsCompressedJarMembers(string name)
    {
        string rules = Path.Combine(_root, "shared-rules");
        Directory.CreateDirectory(rules);
        await File.WriteAllTextAsync(Path.Combine(rules, "fixture.yar"),
            "rule BenignSharedJarFixture { meta: severity = 95 strings: $marker = \"BENIGN SHARED JAR REVIEW MARKER\" condition: $marker }");
        var yara = new AegisPC.Security.Detection.YaraEngine.YaraEngine(rules);
        byte[] member = Encoding.UTF8.GetBytes(new string(' ', 8192) + "BENIGN SHARED JAR REVIEW MARKER" + new string(' ', 8192));
        string path = await CreateArchiveAsync(name, "com/example/Fixture.class", member);
        var hub = DetectionHubFactory.CreateDefault(yaraEngine: yara);
        var result = await hub.EvaluateAsync(new DetectionContext { FilePath = path });
        Assert.Contains(result.Evidences, e => e.Metadata.TryGetValue("ArchiveMember", out string? entry) &&
            entry == "com/example/Fixture.class" && e.Description.Contains("BenignSharedJarFixture", StringComparison.Ordinal));
        Assert.InRange(result.RiskScore, 1, 84);
        Assert.NotEqual(DetectionVerdict.ConfirmedMalicious, result.Verdict);
    }

    [Fact]
    public async Task BenignJarInspection_RecordsBoundedContentCostWithoutKillingAnyProcess()
    {
        byte[] member = Encoding.UTF8.GetBytes(new string(' ', 1024 * 1024) + "BENIGN JAR REVIEW PERFORMANCE MARKER");
        string path = await CreateArchiveAsync("benchmark.jar", "Fixture.class", member);
        using var host = System.Diagnostics.Process.GetCurrentProcess();
        TimeSpan cpuBefore = host.TotalProcessorTime;
        long allocatedBefore = GC.GetTotalAllocatedBytes();
        var timer = System.Diagnostics.Stopwatch.StartNew();
        var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
        timer.Stop();
        host.Refresh();
        _output.WriteLine($"Benign JAR hash/pattern baseline: bytes={member.Length}; elapsed_ms={timer.Elapsed.TotalMilliseconds:F2}; cpu_ms={(host.TotalProcessorTime - cpuBefore).TotalMilliseconds:F2}; rss_mib={host.WorkingSet64 / (1024d * 1024d):F2}; allocated_bytes={GC.GetTotalAllocatedBytes() - allocatedBefore}");
        Assert.True(result.IsComplete);
        Assert.Empty(result.Findings);
    }

    private async Task<string> CreateArchiveAsync(string name, string entry, byte[] bytes)
    {
        string path = Path.Combine(_root, name);
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        using var output = archive.CreateEntry(entry).Open();
        await output.WriteAsync(bytes);
        return path;
    }

    private static string FindProjectRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "AegisPC.sln"))) return directory.FullName;
        throw new DirectoryNotFoundException("Project instruction root was not found.");
    }

    private sealed class RecordingYaraEngine : IYaraEngine
    {
        public bool Throw;
        public List<byte[]> Buffers { get; } = new();
        public int LoadedRuleCount => 1;
        public string RulesDirectory => "inert test-only rules";
        public void ReloadRules() { }
        public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default)
            => throw new InvalidOperationException("Archive inspection must not extract members to disk.");
        public Task<List<YaraMatch>> ScanBufferAsync(byte[] buffer, string identifier = "", CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            if (Throw) throw new IOException("Benign simulated rule engine failure.");
            Buffers.Add(buffer.ToArray());
            return Task.FromResult(new List<YaraMatch> { new() { RuleName = "BenignReviewFixture", Severity = 95, Description = "Explicit inert test-only marker, not malware intelligence" } });
        }
    }
}
