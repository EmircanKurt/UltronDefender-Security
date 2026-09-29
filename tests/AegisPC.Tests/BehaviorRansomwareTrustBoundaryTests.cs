using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

public sealed class BehaviorRansomwareTrustBoundaryTests
{
    [Fact]
    public async Task BehaviorEventsInWritableProductRootStillReachTheAnalyzer()
    {
        string executable = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "UltronDefender", "untrusted-plugin.exe");
        Assert.True(ScanFilterPolicy.IsSelfOwnedPath(executable));

        using var engine = new BehaviorEngine();
        int syntheticPid = int.MaxValue - 123;
        await engine.ProcessEventAsync(new BehaviorEvent
        {
            EventType = BehaviorEventType.ProcessSpawn,
            ProcessId = syntheticPid,
            ProcessName = "synthetic-fixture",
            ExecutablePath = executable
        });

        Assert.NotNull(engine.LineageTracker.GetProcess(syntheticPid));
        Assert.Empty(await engine.GetActiveIncidentsAsync());
    }

    [Fact]
    public void ProductDirectoryOrExecutableNameAloneDoesNotAllowProtectedFolderWrites()
    {
        var gate = CreateInMemoryGate();
        string productRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "UltronDefender", "untrusted-plugin.exe");
        string renamedBinary = Path.Combine(Path.GetTempPath(), "UltronDefender.exe");

        Assert.False(gate.IsApplicationAllowed(productRoot));
        Assert.False(gate.IsApplicationAllowed(renamedBinary));
        Assert.False(gate.IsApplicationAllowed("winword.exe"));
    }

    [Fact]
    public void ExplicitApplicationAllowanceRequiresTheSameCanonicalAbsolutePath()
    {
        var gate = CreateInMemoryGate();
        string allowed = Path.Combine(Path.GetTempPath(), "trusted", "editor.exe");
        string sibling = Path.Combine(Path.GetTempPath(), "untrusted", "editor.exe");
        GetAllowedApps(gate).Add(new AllowedRansomwareApplication { ExecutablePath = allowed });
        GetAllowedApps(gate).Add(new AllowedRansomwareApplication
        {
            ExecutablePath = "winword.exe",
            IsSystemWhitelisted = true
        });

        Assert.True(gate.IsApplicationAllowed(
            Path.Combine(Path.GetTempPath(), "trusted", "folder", "..", "editor.exe")));
        Assert.False(gate.IsApplicationAllowed(sibling));
        Assert.False(gate.IsApplicationAllowed("editor.exe"));
        Assert.False(gate.IsApplicationAllowed("winword.exe"));
    }

    [Fact]
    public void ProtectedDirectoryMembershipRequiresAPathSegmentBoundary()
    {
        var gate = CreateInMemoryGate();
        string root = Path.Combine(Path.GetTempPath(), "protected-documents");
        GetProtectedDirs(gate).Add(root);

        Assert.True(gate.IsPathInsideProtectedDirectory(Path.Combine(root, "file.txt")));
        Assert.False(gate.IsPathInsideProtectedDirectory(
            Path.Combine(Path.GetTempPath(), "protected-documents-bypass", "file.txt")));
        Assert.False(gate.IsPathInsideProtectedDirectory(
            Path.Combine(root, "..", "outside.txt")));
    }

    [Fact]
    public void RansomwareAllowanceDecisionCannotUseOnlyAProcessName()
    {
        var method = typeof(RansomwareEnforcementHandler).GetMethod(
            "IsExplicitlyAllowedProcess", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        Func<string, bool> allowNameOnly = candidate =>
            string.Equals(candidate, "editor", StringComparison.OrdinalIgnoreCase);
        Func<string, bool> allowExactPath = candidate =>
            string.Equals(candidate, @"C:\Program Files\Trusted\editor.exe", StringComparison.OrdinalIgnoreCase);

        Assert.False((bool)method!.Invoke(null,
            new object?[] { "editor", @"C:\Users\User\AppData\evil.exe", allowNameOnly })!);
        Assert.True((bool)method.Invoke(null,
            new object?[] { "editor", @"C:\Program Files\Trusted\editor.exe", allowExactPath })!);
    }

    [Fact]
    public void MsrtTemporaryLocationAloneIsSuspiciousNotConfirmedMalicious()
    {
        var classify = typeof(MsrtRemediationEngine).GetMethod(
            "CreateTemporaryProcessFinding", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(classify);

        string temporaryExecutable = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Temp", "benign-fixture.exe");
        var finding = (SecurityFinding?)classify!.Invoke(null,
            new object[] { temporaryExecutable, "benign-fixture", 12345 });

        Assert.NotNull(finding);
        Assert.Equal(RiskLevel.Suspicious, finding!.RiskLevel);
        Assert.InRange(finding.RiskScore, 1, 65);
    }

    private static ProtectedFolderGate CreateInMemoryGate()
    {
        var gate = (ProtectedFolderGate)RuntimeHelpers.GetUninitializedObject(
            typeof(ProtectedFolderGate));
        typeof(ProtectedFolderGate).GetField("_lock", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(gate, new object());
        typeof(ProtectedFolderGate).GetField("_allowedApps", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(gate, new List<AllowedRansomwareApplication>());
        typeof(ProtectedFolderGate).GetField("_protectedDirs", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(gate, new List<string>());
        return gate;
    }

    private static List<AllowedRansomwareApplication> GetAllowedApps(ProtectedFolderGate gate) =>
        (List<AllowedRansomwareApplication>)typeof(ProtectedFolderGate)
            .GetField("_allowedApps", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(gate)!;

    private static List<string> GetProtectedDirs(ProtectedFolderGate gate) =>
        (List<string>)typeof(ProtectedFolderGate)
            .GetField("_protectedDirs", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(gate)!;
}
