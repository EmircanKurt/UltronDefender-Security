using System.IO;
using System.Reflection;
using System.Text.Json;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.RealTime;
using AegisPC.Service.IPC;
using AegisPC.ServiceContracts.IpcMessages;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Managed optional-review policy and isolated settings fixtures; no installed service, process action, or malware is used.</summary>
public sealed class UltronAiShieldBackendTests
{
    /// <summary>Old settings retain review enabled, but an old status cannot claim the feature was observed.</summary>
    [Fact]
    public void LegacySettingsAndStatus_HaveDistinctDefaults()
    {
        Assert.True(JsonSerializer.Deserialize<AppSettings>("{}")!.IsUltronAiEnabled);
        Assert.Null(JsonSerializer.Deserialize<ProtectionStatus>("{\"ProtectionLevel\":\"legacy\"}")!.IsUltronAiEnabled);
        Assert.Equal(15, (int)ServiceCommandType.GetDeviceInventory);
        Assert.Equal(16, (int)ServiceCommandType.EnableUltronAi);
        Assert.Equal(17, (int)ServiceCommandType.DisableUltronAi);
    }

    /// <summary>The command parser and role map allow only authenticated administrator controls, preserving read-only status.</summary>
    [Theory]
    [InlineData(ServiceCommandType.EnableUltronAi)]
    [InlineData(ServiceCommandType.DisableUltronAi)]
    public void NewControls_RequireVerifiedAdministrator(ServiceCommandType commandType)
    {
        Assert.True(ServiceCommandParser.TryParse(JsonSerializer.Serialize(new ServiceCommand { CommandType = commandType }), out var parsed));
        Assert.Equal(commandType, parsed!.CommandType);
        Assert.False(ServiceControlCommandAuthorization.IsAllowed(commandType, false));
        Assert.True(ServiceControlCommandAuthorization.IsAllowed(commandType, true));
        Assert.True(ServiceControlCommandAuthorization.IsAllowed(ServiceCommandType.GetStatus, false));
        Assert.False(ServiceControlCommandAuthorization.IsAllowed((ServiceCommandType)int.MaxValue, true));
    }

    /// <summary>Disabled review does not invoke the engine, and stale metadata from a reused context is removed without erasing other coverage.</summary>
    [Fact]
    public async Task DisabledReview_ClearsOnlyOwnedContextAndDoesNotInspect()
    {
        var engine = new CountingEngine();
        var plugin = new UltronAiDetectorPlugin(engine, () => false);
        var context = Context();
        context.Properties["UltronAiVerdict"] = new UltronAiVerdict();
        context.Properties["UltronAiReviewPriority"] = 60;
        context.Properties["UltronAiProbability"] = 0.99;
        context.CoverageLimitations.Add("UltronStaticReview: stale");
        context.CoverageLimitations.Add("Other detector limitation");
        Assert.Empty(await plugin.EvaluateAsync(context));
        Assert.Equal(0, engine.Calls);
        Assert.False(plugin.IsReviewEnabled);
        Assert.True(plugin.IsEnabled); // Routing remains present to clean previous AI metadata.
        Assert.Empty(context.Properties);
        Assert.Equal("Other detector limitation", Assert.Single(context.CoverageLimitations));
    }

    /// <summary>A live preference getter changes the existing singleton without rebuilding the hub or changing other detectors.</summary>
    [Fact]
    public async Task LiveToggle_ReusesSamePluginAndResumesReview()
    {
        bool enabled = true;
        var engine = new CountingEngine();
        var plugin = new UltronAiDetectorPlugin(engine, () => enabled);
        var context = Context();
        await plugin.EvaluateAsync(context);
        Assert.True(context.Properties.ContainsKey("UltronAiVerdict"));
        enabled = false;
        await plugin.EvaluateAsync(context);
        Assert.False(context.Properties.ContainsKey("UltronAiVerdict"));
        enabled = true;
        await plugin.EvaluateAsync(context);
        Assert.True(context.Properties.ContainsKey("UltronAiVerdict"));
        Assert.Equal(2, engine.Calls);
    }

    /// <summary>Disabling while analysis awaits cannot publish its completed stale result.</summary>
    [Fact]
    public async Task DisableDuringReview_DiscardsInFlightResult()
    {
        bool enabled = true;
        var engine = new CountingEngine { Deferred = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        var plugin = new UltronAiDetectorPlugin(engine, () => enabled);
        var context = Context();
        Task<IEnumerable<SecurityEvidence>> pending = plugin.EvaluateAsync(context);
        enabled = false;
        engine.Deferred.SetResult(Verdict());
        Assert.Empty(await pending);
        Assert.False(context.Properties.ContainsKey("UltronAiVerdict"));
    }

    /// <summary>A rapid disable/enable cycle with a changed policy revision cannot restore the old awaited review result.</summary>
    [Fact]
    public async Task PolicyChangeDuringReview_DiscardsOldResult()
    {
        var engine = new CountingEngine { Deferred = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        var plugin = new UltronAiDetectorPlugin(engine, () => true);
        var context = Context();
        Task<IEnumerable<SecurityEvidence>> pending = plugin.EvaluateAsync(context);
        DetectionPolicyRevision.Invalidate();
        engine.Deferred.SetResult(Verdict());
        await pending;
        Assert.False(context.Properties.ContainsKey("UltronAiVerdict"));
    }

    /// <summary>Turning review off cannot suppress another detector's exact typed signature evidence.</summary>
    [Fact]
    public async Task DisabledAi_DoesNotDisableAuthoritativeEvidence()
    {
        var engine = new CountingEngine();
        var hub = new DetectionHub(new IDetectorPlugin[] { new SignatureFixture(), new UltronAiDetectorPlugin(engine, () => false) });
        var result = await hub.EvaluateAsync(Context());
        Assert.Equal(0, engine.Calls);
        Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
        Assert.Equal(DetectionPolicy.BlockAndQuarantine, result.RecommendedPolicy);
        Assert.Equal("IndependentSignature", Assert.Single(result.Evidences).SourceDetector);
    }

    /// <summary>The shared factory forwards the live preference only to the optional plugin; no detector is evaluated by this fixture.</summary>
    [Fact]
    public void DefaultFactory_WiresPreferenceWithoutDisablingOtherDetectors()
    {
        bool enabled = false;
        var hub = DetectionHubFactory.CreateDefault(
            hashService: DispatchProxy.Create<IHashService, NoProtectionActionsProxy>(),
            signatureVerifier: DispatchProxy.Create<ISignatureVerifier, NoProtectionActionsProxy>(),
            deepPeAnalyzer: DispatchProxy.Create<AegisPC.Contracts.PE.IDeepPeAnalyzer, NoProtectionActionsProxy>(),
            antiEvasionDetector: DispatchProxy.Create<AegisPC.Contracts.AntiEvasion.IAntiEvasionDetector, NoProtectionActionsProxy>(),
            secureArchiveEngine: DispatchProxy.Create<AegisPC.Contracts.Archive.ISecureArchiveEngine, NoProtectionActionsProxy>(),
            yaraEngine: DispatchProxy.Create<AegisPC.Security.Detection.YaraEngine.IYaraEngine, NoProtectionActionsProxy>(),
            threatStore: DispatchProxy.Create<AegisPC.Contracts.ThreatIntelligence.IThreatIntelligenceStore, NoProtectionActionsProxy>(),
            isUltronAiEnabled: () => enabled);
        var plugin = Assert.Single(hub.RegisteredDetectors.OfType<UltronAiDetectorPlugin>());
        Assert.False(plugin.IsReviewEnabled);
        enabled = true;
        Assert.True(plugin.IsReviewEnabled);
        Assert.All(hub.RegisteredDetectors.Where(item => item != plugin), item => Assert.True(item.IsEnabled));
    }

    /// <summary>A service without a wired plugin reports the feature unobserved, not optimistically enabled from settings.</summary>
    [Fact]
    public void MissingServicePlugin_ReportsUnobservedReview()
    {
        var settings = new SettingsService(FixtureSettingsPath());
        using var server = Server(settings, new DetectionHub());
        Assert.Null(CurrentStatus(server).IsUltronAiEnabled);
    }

    /// <summary>The source command handler saves to an isolated fixture and acknowledges the wired preference rather than independent RT protection.</summary>
    [Fact]
    public async Task ServiceToggle_PersistsAndReportsWiredReview()
    {
        string path = FixtureSettingsPath();
        try
        {
            var settings = new SettingsService(path);
            var plugin = new UltronAiDetectorPlugin(new CountingEngine(), () => settings.Current.IsUltronAiEnabled);
            using var server = Server(settings, new DetectionHub(new[] { plugin }));
            Assert.True(CurrentStatus(server).IsUltronAiEnabled);
            await SetPreference(server, false);
            Assert.False(CurrentStatus(server).IsUltronAiEnabled);
            Assert.False(CurrentStatus(server).IsRealTimeEnabled);
            var reloaded = new SettingsService(path);
            await reloaded.LoadAsync();
            Assert.False(reloaded.Current.IsUltronAiEnabled);
            await SetPreference(server, true);
            await reloaded.LoadAsync();
            Assert.True(reloaded.Current.IsUltronAiEnabled);
        }
        finally { if (Directory.Exists(Path.GetDirectoryName(path))) Directory.Delete(Path.GetDirectoryName(path)!, true); }
    }

    /// <summary>Persistence failure restores the old preference; it cannot become a successful disabled status.</summary>
    [Fact]
    public async Task FailedPersistence_RestoresPreviousPreference()
    {
        string folder = Path.Combine(Path.GetTempPath(), "UltronAiPolicyFixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var settings = new SettingsService(folder); // A directory cannot be replaced with a settings file.
            var plugin = new UltronAiDetectorPlugin(new CountingEngine(), () => settings.Current.IsUltronAiEnabled);
            using var server = Server(settings, new DetectionHub(new[] { plugin }));
            await Assert.ThrowsAnyAsync<IOException>(() => SetPreference(server, false));
            Assert.True(settings.Current.IsUltronAiEnabled);
            Assert.True(CurrentStatus(server).IsUltronAiEnabled);
        }
        finally { Directory.Delete(folder, true); }
    }

    /// <summary>A missing feature cannot accept a preference command or create a settings file.</summary>
    [Fact]
    public async Task MissingServicePlugin_CannotAcknowledgeChange()
    {
        string path = FixtureSettingsPath();
        var settings = new SettingsService(path);
        using var server = Server(settings, new DetectionHub());
        await Assert.ThrowsAsync<InvalidOperationException>(() => SetPreference(server, false));
        Assert.True(settings.Current.IsUltronAiEnabled);
        Assert.False(File.Exists(path));
    }

    private static DetectionContext Context() => new() { FilePath = "inert-fixture", ContentClassification = new(),
        SharedScan = new ScanContext("inert-fixture") { LockedContent = Stream.Null } };
    private static UltronAiVerdict Verdict() => new() { CalculatedRiskScore = 40, Coverage = ContentClassificationCoverage.Complete };
    private static string FixtureSettingsPath() => Path.Combine(Path.GetTempPath(), "UltronAiPolicyFixture-" + Guid.NewGuid().ToString("N"), "settings.json");
    private static NamedPipeServer Server(SettingsService settings, IDetectionHub hub) => new(
        NullLogger<NamedPipeServer>.Instance,
        DispatchProxy.Create<IBackgroundProtectionService, NoProtectionActionsProxy>(),
        DispatchProxy.Create<IRealTimeProtectionEngine, NoProtectionActionsProxy>(),
        DispatchProxy.Create<IRansomwareProtectionEngine, NoProtectionActionsProxy>(), settings, detectionHub: hub);
    private static ProtectionStatus CurrentStatus(NamedPipeServer server) => (ProtectionStatus)typeof(NamedPipeServer)
        .GetMethod("BuildCurrentStatus", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(server, new object[] { Guid.Empty })!;
    private static Task SetPreference(NamedPipeServer server, bool enabled) => (Task)typeof(NamedPipeServer)
        .GetMethod("SetUltronAiReviewEnabledAsync", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(server, new object[] { enabled })!;

    private sealed class CountingEngine : IUltronAiEngine
    {
        internal int Calls;
        internal TaskCompletionSource<UltronAiVerdict>? Deferred;
        /// <summary>Counts inert path calls without opening a file.</summary>
        public Task<UltronAiVerdict> EvaluateFileAsync(string path, CancellationToken cancellationToken = default) => Evaluate();
        /// <summary>Counts inert borrowed-content calls without consuming or closing the stream.</summary>
        public Task<UltronAiVerdict> EvaluateLockedFileAsync(Stream source, string path, FileContentClassification classification,
            CancellationToken cancellationToken = default) => Evaluate();
        /// <summary>Returns fixture review metadata without authorizing an action.</summary>
        public UltronAiVerdict EvaluateVector(UltronFeatureVector vector) => Verdict();
        private Task<UltronAiVerdict> Evaluate() { Calls++; return Deferred?.Task ?? Task.FromResult(Verdict()); }
    }

    private sealed class SignatureFixture : IDetectorPlugin
    {
        /// <summary>Identifies evidence independently of AI review.</summary>
        public string DetectorId => "IndependentSignature";
        /// <summary>Labels the synthetic evidence-policy fixture.</summary>
        public string DisplayName => "Inert signature-policy fixture";
        /// <summary>Supplies a typed authoritative category for a managed policy assertion only.</summary>
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticSignature;
        /// <summary>Runs before the optional static review router.</summary>
        public int Priority => 1;
        /// <summary>Keeps this independent detector active across optional-review toggles.</summary>
        public bool IsEnabled { get; set; } = true;
        /// <summary>Returns synthetic signature evidence; no hash, provider or malware sample is invoked.</summary>
        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default) =>
            Task.FromResult<IEnumerable<SecurityEvidence>>(new[] { new SecurityEvidence { SourceDetector = DetectorId,
                Category = PrimaryCategory, Confidence = EvidenceConfidence.Absolute, ScoreContribution = 100,
                RuleName = "TypedExactSignatureFixture", FilePath = context.FilePath } });
    }

    /// <summary>Allows read-only fixture properties/events but rejects all attempts to operate actual protection engines.</summary>
    public class NoProtectionActionsProxy : DispatchProxy
    {
        /// <summary>Returns inactive property defaults and inert event subscriptions; any action is a fixture failure.</summary>
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod == null) throw new InvalidOperationException("Missing fixture method.");
            if (targetMethod.Name.StartsWith("add_", StringComparison.Ordinal) || targetMethod.Name.StartsWith("remove_", StringComparison.Ordinal)) return null;
            if (targetMethod.Name.StartsWith("get_", StringComparison.Ordinal))
                return targetMethod.ReturnType.IsValueType ? Activator.CreateInstance(targetMethod.ReturnType) : null;
            throw new InvalidOperationException("Native protection actions are forbidden in this fixture.");
        }
    }
}
