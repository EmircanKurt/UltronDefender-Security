using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests;

/// <summary>
/// Verifies observed user-mode ransomware health with in-memory canary/gate/enforcement dependencies.
/// Real watchers are restricted to unique empty temporary roots; no user canaries, settings, processes or vault are touched.
/// </summary>
public sealed class RansomwareObserverHealthTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NoExistingProtectedRoots_DoesNotClaimActiveObservation(bool includeMissingRoot)
    {
        string absent = Path.Combine(Path.GetTempPath(), "Ultron_Ransomware_Missing_" + Guid.NewGuid().ToString("N"));
        Assert.False(Directory.Exists(absent));
        var canary = new InertCanary();
        var gate = new InertFolderGate(includeMissingRoot ? new[] { absent } : Array.Empty<string>());
        using var engine = Engine(canary, gate);

        engine.StartShield();

        Assert.False(engine.IsShieldActive);
        Assert.Equal(0, engine.CaptureRansomwareCoverage().WatcherCount);
        Assert.True(engine.CaptureRansomwareCoverage().HasUnresolvedGap);
        Assert.Empty(canary.CanaryFiles);
        Assert.False(Directory.Exists(absent));
    }

    [Fact]
    public void CanaryInitializationFailure_CannotClaimActiveObservation()
    {
        using var root = new TemporaryRoot();
        var canary = new InertCanary(failDeployment: true);
        var enforcement = new InertEnforcement();
        using var engine = Engine(canary, new InertFolderGate(new[] { root.Path }), enforcement);

        Assert.Throws<IOException>(() => engine.StartShield());

        Assert.False(engine.IsShieldActive);
        Assert.Equal(0, engine.CaptureRansomwareCoverage().WatcherCount);
        Assert.True(engine.CaptureRansomwareCoverage().HasUnresolvedGap);
        Assert.Equal(0, enforcement.Calls);
        Assert.Empty(Directory.EnumerateFileSystemEntries(root.Path));
    }

    [Fact]
    public void ActiveTemporaryRoot_WatcherErrorKeepsContinuityGapVisibleAfterRestart()
    {
        using var root = new TemporaryRoot();
        var canary = new InertCanary();
        var enforcement = new InertEnforcement();
        using var engine = Engine(canary, new InertFolderGate(new[] { root.Path }), enforcement);
        engine.StartShield();
        Assert.True(engine.IsShieldActive);
        Assert.Equal(1, engine.CaptureRansomwareCoverage().WatcherCount);
        Assert.False(engine.CaptureRansomwareCoverage().HasUnresolvedGap);
        var watchers = (List<FileSystemWatcher>)typeof(RansomwareProtectionEngine)
            .GetField("_watchers", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(engine)!;
        var watcher = Assert.Single(watchers);
        var raiseError = typeof(FileSystemWatcher).GetMethod("OnError", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(raiseError);

        // Injects a lost-event notification; no real overflow, destructive operation or ransomware is generated.
        raiseError!.Invoke(watcher, new object[] { new ErrorEventArgs(new InternalBufferOverflowException("Inert lost-event fixture.")) });

        Assert.True(engine.CaptureRansomwareCoverage().HasUnresolvedGap);
        Assert.Equal(1, engine.CaptureRansomwareCoverage().WatcherCount);
        Assert.True(engine.IsShieldActive); // Active observation does not mean uninterrupted coverage.
        Assert.Equal(0, enforcement.Calls);
        Assert.Empty(Directory.EnumerateFileSystemEntries(root.Path));
        engine.StopShield();
        Assert.False(engine.IsShieldActive);
        Assert.Equal(0, engine.CaptureRansomwareCoverage().WatcherCount);
    }

    private static RansomwareProtectionEngine Engine(InertCanary canary, InertFolderGate gate,
        InertEnforcement? enforcement = null) => new(canary, new InertEntropy(), gate, enforcement ?? new InertEnforcement());

    /// <summary>A declared UNC root is never sent to canary deployment or opened by a native watcher.</summary>
    [Fact]
    public void NetworkRoot_IsOmittedAndObservationRemainsPartial()
    {
        var canary = new InertCanary();
        using var engine = Engine(canary, new InertFolderGate([@"\\server.invalid\share"]));
        engine.StartShield();
        Assert.Empty(canary.DeploymentRoots);
        var eligibleRoots = typeof(RansomwareProtectionEngine).GetMethod("GetEligibleProtectionRoots", BindingFlags.Instance | BindingFlags.NonPublic)!;
        Assert.Empty((string[])eligibleRoots.Invoke(engine, null)!); // Redeployment uses this same filter.
        Assert.False(engine.IsShieldActive);
        Assert.Equal(0, engine.CaptureRansomwareCoverage().WatcherCount);
        Assert.True(engine.CaptureRansomwareCoverage().HasUnresolvedGap);
    }

    private sealed class InertCanary : ICanaryTrapManager
    {
        private readonly bool _failDeployment;
        public InertCanary(bool failDeployment = false) { _failDeployment = failDeployment; }
        public int CanaryFileCount => 0;
        internal IReadOnlyList<string> DeploymentRoots { get; private set; } = [];
        public bool IsCleaningUpCanaries => false;
        public IReadOnlyList<string> CanaryFiles => Array.Empty<string>();
        public void DeployCanaries(IEnumerable<string> protectedDirs)
        { DeploymentRoots = protectedDirs.ToArray(); if (_failDeployment) throw new IOException("Inert canary initialization failure."); }
        public void CleanupCanaries() { }
        public bool IsCanaryPath(string path) => false;
    }

    private sealed class InertEntropy : IEntropyBurstDetector
    {
        public bool IsKnownRansomwareExtension(string ext) => false;
        public Task CheckEntropyDeltaAsync(string fullPath, Func<string, string, int, Task> onThreatDetected) => Task.CompletedTask;
        public void CheckRansomwareBurst(string path, string operation, Func<string, string, int, Task> onThreatDetected) { }
        public void Clear() { }
        public void Dispose() { }
    }

    private sealed class InertFolderGate : IProtectedFolderGate
    {
        private readonly List<string> _roots;
        public InertFolderGate(IEnumerable<string> roots) { _roots = new List<string>(roots); }
        public IReadOnlyList<string> ProtectedDirectories => _roots;
        public IReadOnlyList<AllowedRansomwareApplication> AllowedApplications => Array.Empty<AllowedRansomwareApplication>();
        public void AddProtectedDirectory(string path) => _roots.Add(path);
        public void RemoveProtectedDirectory(string path) => _roots.Remove(path);
        public void AddAllowedApplication(string executablePath, string? appName = null) { }
        public void RemoveAllowedApplication(string executablePath) { }
        public bool IsPathInsideProtectedDirectory(string path) => false;
        public bool IsApplicationAllowed(string executablePath) => true;
    }

    private sealed class InertEnforcement : IRansomwareEnforcementHandler
    {
        public int Calls { get; private set; }
        public int TotalBlockedAttempts => 0;
        public event EventHandler<RansomwareAlertEventArgs>? OnRansomwareAttemptDetected { add { } remove { } }
        public event Action<string, string, string>? OnNotificationRaised { add { } remove { } }
        public Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(string offendingPath, string reason,
            int riskScore, int pid = 0, Func<string, bool>? isAppAllowed = null, DateTime? incidentTimestamp = null)
        { Calls++; return Task.FromResult<RansomwareDamageAssessment?>(null); }
    }

    private sealed class TemporaryRoot : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "Ultron_Ransomware_Observer_" + Guid.NewGuid().ToString("N"));
        public TemporaryRoot() { Directory.CreateDirectory(Path); }
        public void Dispose()
        {
            // Only the explicitly created empty GUID root is removed, after engine/watchers are disposed.
            // Unexpected files make cleanup fail instead of deleting material not owned by this fixture.
            if (Directory.Exists(Path)) Directory.Delete(Path, recursive: false);
        }
    }
}
