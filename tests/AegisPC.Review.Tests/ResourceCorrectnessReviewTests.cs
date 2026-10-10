using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.PE;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert resource, evidence and binary-structure fixtures; no malware, services or native actions.</summary>
public sealed class ResourceCorrectnessReviewTests
{
    [Theory]
    [InlineData(2048, 256)]
    [InlineData(4096, 256)]
    [InlineData(8192, 512)]
    [InlineData(12288, 1024)]
    [InlineData(16252, 2048)]
    [InlineData(32768, 2048)]
    public void UsefulBudget_LeavesHeadroomRatherThanFillingRam(int ramMb, int expectedMb)
    {
        var profile = ScanResourceProfile.Create(ScanResourceMode.Auto, false, 12, ramMb * 1048576L, 15, 50);
        Assert.Equal(expectedMb * 1048576L, profile.MaxMemoryBudgetBytes);
        Assert.Equal(4, profile.Concurrency);
        Assert.Equal(ramMb >= 15360 ? 60 : 40, profile.CpuTargetPercent);
    }

    [Theory]
    [InlineData(70, 50)]
    [InlineData(20, 85)]
    [InlineData(double.NaN, double.NaN)]
    public void BusyOrMissingMeasurement_DoesNotExpand(double cpu, double memory)
    {
        var profile = ScanResourceProfile.Create(ScanResourceMode.Maximum, false, 12, 16L << 30, cpu, memory);
        Assert.InRange(profile.Concurrency, 1, 2);
        Assert.NotEmpty(profile.LimitingReason);
        Assert.False(profile.IsAdmissionPaused);
    }

    [Fact]
    public async Task CriticalMemory_DefersAdmission_AndCancelsWithoutStrandedWorkers()
    {
        double pressure = 92;
        using var resources = new AdaptiveScanResourceManager(storageClassifier: _ => true,
            pressureSampler: () => (pressure, 10, false), enableTelemetryTimer: false);
        Assert.True(resources.ActiveProfile.IsAdmissionPaused);
        using var cancelled = new CancellationTokenSource();
        var waiting = resources.EnterWorkerSlotAsync(cancelled.Token);
        Assert.False(waiting.IsCompleted);
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting.WaitAsync(TimeSpan.FromSeconds(2)));
        pressure = 50;
        for (int i = 0; i < 3; i++) resources.RefreshProfile(); // Expansion requires three healthy samples.
        await resources.EnterWorkerSlotAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2));
        resources.ExitWorkerSlot();
    }

    [Fact]
    public async Task CapabilitiesAcrossDetectors_DoNotBecomeMalware_AndCanonicalFeatureIsCountedOnce()
    {
        var hub = new DetectionHub();
        hub.RegisterDetector(new EvidencePlugin([
            Capability("PE.Api.IsDebuggerPresent", EvidenceCategory.StaticApi, 25),
            Capability("PE.Api.IsDebuggerPresent", EvidenceCategory.AntiEvasion, 35),
            Capability("PE.Entropy", EvidenceCategory.StaticPeStructure, 25),
            Capability("PE.Unsigned", EvidenceCategory.DigitalCertificate, 10),
            Capability("PE.PackingCapability", EvidenceCategory.StaticPeStructure, 30)
        ]));
        var verdict = await hub.EvaluateAsync(new DetectionContext { FilePath = "fixture.exe" });
        Assert.Equal(4, verdict.Evidences.Count);
        Assert.InRange(verdict.RiskScore, 0, 25);
        Assert.Equal(DetectionVerdict.Clean, verdict.Verdict);
        Assert.Equal(DetectionPolicy.Allow, verdict.RecommendedPolicy);
    }

    [Fact]
    public async Task CapabilityCap_CannotBeBypassedBySharingAnAnomalyGroup()
    {
        var items = Enumerable.Range(0, 8).Select(i => Capability("feature" + i, EvidenceCategory.StaticApi, 80)).ToList();
        items.Add(new SecurityEvidence { Category = EvidenceCategory.StaticApi, ScoreContribution = 1,
            Nature = EvidenceNature.StructuralAnomaly, RuleName = "fixture anomaly" });
        var hub = new DetectionHub();
        hub.RegisterDetector(new EvidencePlugin(items));
        var result = await hub.EvaluateAsync(new DetectionContext());
        Assert.InRange(result.RiskScore, 0, 26);
    }

    [Fact]
    public async Task ValidSignatureAndCapabilityDuplicates_DoNotEraseIndependentExactMalwareEvidence()
    {
        var signature = new SecurityEvidence { FeatureIdentity = "same", Category = EvidenceCategory.StaticSignature,
            ScoreContribution = 100, Confidence = EvidenceConfidence.Absolute, RuleName = "inert test identity" };
        var hub = new DetectionHub();
        hub.RegisterDetector(new EvidencePlugin([Capability("same", EvidenceCategory.StaticApi, 200), signature,
            new SecurityEvidence { Category = EvidenceCategory.DigitalCertificate, ScoreContribution = -50,
                TrustKind = EvidenceTrustKind.VerifiedAuthenticode, RuleName = "inert verified certificate" }]));
        var result = await hub.EvaluateAsync(new DetectionContext());
        Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
        Assert.Equal(DetectionPolicy.BlockAndQuarantine, result.RecommendedPolicy);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TlsDirectoryWithoutCallbacks_IsNotCallbackExecution(bool wide)
    {
        var bytes = TlsFixture(wide, false);
        var result = TlsCallbackInspector.Inspect(bytes);
        Assert.True(result.HasDirectory);
        Assert.True(result.Complete);
        Assert.Equal(0, result.CallbackCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ValidTlsCallbacks_AreCountedButRemainOrdinaryCapabilities(bool wide)
    {
        var result = TlsCallbackInspector.Inspect(TlsFixture(wide, true));
        Assert.True(result.Complete);
        Assert.Equal(1, result.CallbackCount);
    }

    [Fact]
    public void CorruptTlsPointer_IsIncomplete_NotAnInventedCallback()
    {
        var bytes = TlsFixture(false, true);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x20c), uint.MaxValue);
        var result = TlsCallbackInspector.Inspect(bytes);
        Assert.False(result.Complete);
        Assert.Equal(0, result.CallbackCount);
    }

    [Fact]
    public async Task VolumeRoundRobin_DoesNotLetOneHddOccupyEveryWorker()
    {
        var queue = new VolumeScanQueue<string>(64, s => s[..1], root => root == "H" ? 1 : 4);
        await queue.WriteAsync("H1", default);
        await queue.WriteAsync("H2", default);
        await queue.WriteAsync("S1", default);
        using var first = await queue.ReadAsync(default);
        using var second = await queue.ReadAsync(default);
        Assert.Equal("H1", first!.Item);
        Assert.Equal("S1", second!.Item);
        var pending = queue.ReadAsync(default);
        Assert.False(pending.IsCompleted);
        first.Dispose();
        using var third = await pending.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal("H2", third!.Item);
        queue.Complete();
        Assert.Null(await queue.ReadAsync(default));
    }

    [Fact]
    public async Task BoundedVolumeWriter_CancelsWithoutLosingItsCapacity()
    {
        var queue = new VolumeScanQueue<int>(1, _ => "same", _ => 1);
        await queue.WriteAsync(1, default);
        using var cancel = new CancellationTokenSource();
        var blocked = queue.WriteAsync(2, cancel.Token);
        Assert.False(blocked.IsCompleted);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => blocked);
        using var lease = await queue.ReadAsync(default);
        await queue.WriteAsync(3, default);
        lease!.Dispose();
        using var next = await queue.ReadAsync(default);
        Assert.Equal(3, next!.Item);
    }

    [Fact]
    public async Task VolumeLimit_DoesNotRemainFrozenAtTheInitialLowPressureProfile()
    {
        int limit = 1;
        var queue = new VolumeScanQueue<int>(8, _ => "same", _ => limit);
        await queue.WriteAsync(1, default);
        await queue.WriteAsync(2, default);
        using var one = await queue.ReadAsync(default);
        var waiting = queue.ReadAsync(default);
        Assert.False(waiting.IsCompleted);
        limit = 4;
        await queue.WriteAsync(3, default); // Publishes a scheduling wake-up.
        using var two = await waiting.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(2, two!.Item);
    }

    [Fact]
    public async Task RealTimeArrival_DefersNewBulkWork_AndReleaseIsIdempotent()
    {
        var arrival = RealtimeScanPriority.Enter();
        var bulk = RealtimeScanPriority.WaitAsync(default);
        Assert.False(bulk.IsCompleted);
        arrival.Dispose(); arrival.Dispose();
        await bulk.WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public void AutomaticExpansion_RequiresThreeStableSamples_AndUndoesUnproductiveTrial()
    {
        using var resources = new AdaptiveScanResourceManager(storageClassifier: _ => true,
            pressureSampler: () => (50, 10, false), enableTelemetryTimer: false, workloadSampler: () => (5, 1));
        Assert.Equal(4, resources.ActiveProfile.Concurrency);
        for (int i = 0; i < 3; i++) SampleWork(resources, 100);
        Assert.Equal(5, resources.ActiveProfile.Concurrency);
        SampleWork(resources, 100);
        Assert.Equal(4, resources.ActiveProfile.Concurrency);
        Assert.Contains("verim", resources.ActiveProfile.LimitingReason);
    }

    [Fact]
    public void MissingDiskMeasurement_NeverDrivesAnAutomaticIncrease()
    {
        using var resources = new AdaptiveScanResourceManager(storageClassifier: _ => true,
            pressureSampler: () => (50, 10, false), enableTelemetryTimer: false, workloadSampler: () => (5, null));
        for (int i = 0; i < 7; i++) SampleWork(resources, 100);
        Assert.Equal(4, resources.ActiveProfile.Concurrency);
        Assert.Contains("ölçümü alınamadı", resources.ActiveProfile.SummaryText);
    }

    /// <summary>Missing startup CPU telemetry contracts safely without freezing admission after actual readings recover.</summary>
    [Fact]
    public void InitialMissingTelemetry_DoesNotPermanentlyFreezeTheSsdStartingPolicy()
    {
        double systemCpu = double.NaN;
        double? scannerCpu = null;
        using var resources = new AdaptiveScanResourceManager(storageClassifier: _ => true,
            pressureSampler: () => (50, systemCpu, false), enableTelemetryTimer: false, workloadSampler: () => (scannerCpu, 1));
        Assert.InRange(resources.ActiveProfile.Concurrency, 1, 2);
        systemCpu = 10; scannerCpu = 5;
        resources.RefreshProfile();
        Assert.Equal(4, resources.ActiveProfile.Concurrency);
        Assert.DoesNotContain("NaN", resources.ActiveProfile.SummaryText);
    }

    [Fact]
    public void BusyCpuOrDisk_ContractsImmediately_AndDoesNotHideRequestedMode()
    {
        double cpu = 5, latency = 1;
        using var resources = new AdaptiveScanResourceManager(storageClassifier: _ => true,
            pressureSampler: () => (50, 20, false), enableTelemetryTimer: false, workloadSampler: () => (cpu, latency));
        cpu = 75; // Exceeds both the capable-machine target and the conservative target.
        resources.RefreshProfile();
        Assert.Equal(2, resources.ActiveProfile.Concurrency);
        Assert.Equal(ScanResourceMode.Auto, resources.CurrentMode);
        cpu = 5; latency = 30;
        resources.RefreshProfile();
        Assert.Equal(1, resources.ActiveProfile.Concurrency);
        Assert.Contains("Disk", resources.ActiveProfile.LimitingReason);
    }

    private static void SampleWork(AdaptiveScanResourceManager resources, int completed)
    {
        resources.ReportCompletedFiles(completed);
        typeof(AdaptiveScanResourceManager).GetField("_throughputSampleAt", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(resources, Stopwatch.GetTimestamp() - Stopwatch.Frequency * 3);
        resources.RefreshProfile();
    }

    /// <summary>A long file without completed work cannot disprove an admission trial; actual CPU pressure still wins.</summary>
    [Fact]
    public void ZeroCompletionDuringLargeFile_HoldsTrialButDoesNotIgnorePressure()
    {
        double cpu = 5;
        using var resources = new AdaptiveScanResourceManager(storageClassifier: _ => true,
            pressureSampler: () => (50, 20, false), enableTelemetryTimer: false, workloadSampler: () => (cpu, 1));
        for (int i = 0; i < 3; i++) SampleWork(resources, 100);
        Assert.Equal(5, resources.ActiveProfile.Concurrency);
        for (int i = 0; i < 4; i++) SampleWork(resources, 0);
        Assert.Equal(5, resources.ActiveProfile.Concurrency);
        Assert.DoesNotContain("verim", resources.ActiveProfile.LimitingReason);
        cpu = 90; resources.RefreshProfile();
        Assert.Equal(2, resources.ActiveProfile.Concurrency);
    }

    [Fact]
    public void MeasurementScope_IsBounded_Idempotent_AndKeepsUnknownStagesUnknown()
    {
        using var measurements = new ScanMeasurementRecorder();
        long queued = Stopwatch.GetTimestamp() - Stopwatch.Frequency;
        using var first = measurements.Begin(@"C:\UltronBenignFixture\one.bin", queued);
        using var second = measurements.Begin(@"D:\UltronBenignFixture\two.bin", queued);
        first.Dispose(); first.Dispose(); second.Dispose();
        var report = measurements.Snapshot();
        Assert.Equal(2, report.Volumes.Count);
        Assert.All(report.Volumes, v => { Assert.Equal(1, v.FinishedAttempts); Assert.Equal(1, v.PeakActiveWorkers); Assert.InRange(v.QueueP95UpperBoundMs, 1024, 2048); });
        Assert.Null(report.HashStageMs);
        Assert.Null(report.ContentStageMs);
    }

    private static SecurityEvidence Capability(string feature, EvidenceCategory category, int score) =>
        new() { FeatureIdentity = feature, Category = category, Nature = EvidenceNature.Capability,
            ScoreContribution = score, RuleName = feature, Confidence = EvidenceConfidence.High };

    private sealed class EvidencePlugin(IEnumerable<SecurityEvidence> evidence) : IDetectorPlugin
    {
        public string DetectorId => "inert";
        public string DisplayName => "inert";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticApi;
        public int Priority => 1;
        public bool IsEnabled { get; set; } = true;
        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken ct = default) => Task.FromResult(evidence);
    }

    private static byte[] TlsFixture(bool wide, bool callbacks)
    {
        var b = new byte[2048];
        b[0] = 0x4d; b[1] = 0x5a;
        void U16(int p, ushort v) => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(p), v);
        void U32(int p, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(p), v);
        void U64(int p, ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(p), v);
        U32(60, 0x80); U32(0x80, 0x4550); U16(0x86, 1);
        int size = wide ? 240 : 224, optional = 0x98, dirs = optional + (wide ? 112 : 96);
        U16(0x94, (ushort)size); U16(optional, wide ? (ushort)0x20b : (ushort)0x10b);
        U32(optional + 60, 512); U32(dirs - 4, 16); U32(dirs + 72, 0x1000); U32(dirs + 76, wide ? 40u : 24u);
        ulong image = wide ? 0x140000000UL : 0x400000UL;
        if (wide) U64(optional + 24, image); else U32(optional + 28, (uint)image);
        int section = optional + size;
        U32(section + 12, 0x1000); U32(section + 16, 1536); U32(section + 20, 512);
        if (callbacks)
        {
            if (wide) { U64(0x218, image + 0x1100); U64(0x300, image + 0x1200); }
            else { U32(0x20c, (uint)image + 0x1100); U32(0x300, (uint)image + 0x1200); }
        }
        return b;
    }
}
