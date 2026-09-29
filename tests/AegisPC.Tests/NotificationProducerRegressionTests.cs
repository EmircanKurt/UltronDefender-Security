using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using AegisPC.App.ViewModels;
using AegisPC.App.Views;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Checks notification contracts without starting WPF, protection engines, or a live service.</summary>
public class NotificationProducerRegressionTests
{
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void EmptyTitleDoesNotClaimAThreatWasBlocked(string title)
        => Assert.Equal("Ultron Defender bildirimi", ToastNotificationWindow.CleanTitle(title));

    [Fact]
    public void ToastSeverityDoesNotInventContainmentOrProtectionState()
    {
        var source = ReadSource("src/AegisPC.App/Views/ToastNotificationWindow.xaml.cs");
        Assert.DoesNotContain("ToastActionStatus.Text = \"Dosya AES-256 Karantina Kasasına kilitlendi.\"", source);
        Assert.DoesNotContain("ToastActionStatus.Text = \"Sistem tamamen temiz ve güvende.\"", source);
        Assert.DoesNotContain("ToastActionStatus.Text = \"Ultron Defender gerçek zamanlı koruma aktif.\"", source);
    }

    [Fact]
    public void ToastLayoutIsQuietAndContainsNoPrefilledThreatClaims()
    {
        var source = ReadSource("src/AegisPC.App/Views/ToastNotificationWindow.xaml");
        Assert.DoesNotContain("Text=\"Tehdit engellendi", source);
        Assert.DoesNotContain("x:Name=\"IconBadge\"", source);
        Assert.DoesNotContain("x:Name=\"HeaderBadge\"", source);
        Assert.Contains("Content=\"Ayrıntılar\"", source);
        Assert.Contains("Width=\"380\"", source);
    }

    [Fact]
    public void ToastDoesNotPulseOrSlideToDemandAttention()
    {
        var source = ReadSource("src/AegisPC.App/Views/ToastNotificationWindow.xaml.cs");
        Assert.DoesNotContain("StartStripePulseAnimation", source);
        Assert.DoesNotContain("CardTranslate.Y = 40", source);
    }

    [Fact]
    public void ApplicationDoesNotDuplicateScanViewModelCompletionToasts()
        => Assert.DoesNotContain("scanCoordinator.ScanCompleted +=", ReadSource("src/AegisPC.App/App.xaml.cs"));

    [Fact]
    public void DetectionEventDoesNotClaimEtwTerminationSucceeded()
    {
        var source = ReadSource("src/AegisPC.App/App.xaml.cs");
        Assert.DoesNotContain("ETW Tehdit Engellendi:", source);
        Assert.DoesNotContain("Zararlı komut çalıştıran süreç durduruldu", source);
    }

    [Fact]
    public void ClosingAFindingDoesNotProveQuarantineInIpc()
    {
        var source = ReadSource("src/AegisPC.Service/IPC/NamedPipeServer.cs");
        Assert.DoesNotContain("ActionTaken = finding.Status == FindingStatus.Resolved", source);
        Assert.DoesNotContain("if (finding.Status == FindingStatus.Resolved)\n                Interlocked.Increment", source.Replace("\r\n", "\n"));
    }

    [Fact]
    public void StartupToastUsesActualQuarantineOutcome()
        => Assert.DoesNotContain("TriggerThreatToast(f.FileName, isQuarantined: true)", ReadSource("src/AegisPC.App/ViewModels/DashboardViewModel.cs"));

    [Fact]
    public void StartupProducerPublishesTheActualQuarantineOutcome()
    {
        var source = ReadSource("src/AegisPC.Security/Scanning/StartupSecuritySweepService.cs");
        Assert.DoesNotContain("Action = \"QUARANTINED\",", source);
        Assert.Contains("finding.Action = quarantined ? \"QUARANTINED\" : \"QUARANTINE_FAILED\"", source);
    }

    [Fact]
    public void StartupFindingListIsClearedForEachNewSweep()
    {
        var source = ReadSource("src/AegisPC.App/ViewModels/DashboardViewModel.cs");
        Assert.Contains("StartupSweepFindings.Clear()", source);
    }

    [Fact]
    public void DangerSeverityDoesNotProveQuarantineOnDashboard()
        => Assert.DoesNotContain("act.Action == \"QUARANTINED\" || act.Severity == \"Danger\"", ReadSource("src/AegisPC.App/ViewModels/DashboardViewModel.cs"));

    [Fact]
    public void MixedDashboardBatchDoesNotClaimEveryObservationWasQuarantined()
    {
        var source = ReadSource("src/AegisPC.App/ViewModels/DashboardViewModel.Telemetry.cs");
        Assert.DoesNotContain("{list.Count} adet zararlı tehdit engellendi ve karantinaya alındı", source);
        Assert.Contains("int quarantined =", source);
    }

    [Fact]
    public void QuarantineMustBeExplicitlyConfirmedByTheCaller()
    {
        var method = typeof(DashboardViewModel).GetMethod(nameof(DashboardViewModel.TriggerThreatToast), BindingFlags.Public | BindingFlags.Instance)!;
        Assert.Equal(false, method.GetParameters()[1].DefaultValue);
    }

    [Theory]
    [InlineData(0, "0 karantinaya alındı, 3 şüpheli bulgu", "Warning")]
    [InlineData(1, "1 karantinaya alındı, 2 şüpheli bulgu", "Warning")]
    [InlineData(3, "3 karantinaya alındı, 0 şüpheli bulgu", "Danger")]
    public void DashboardBatchCountsActualOutcomes(int successes, string expected, string expectedType)
    {
        var method = typeof(DashboardViewModel).GetMethod("BuildThreatToastSummary", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var observations = new List<(string Name, bool IsQuarantined)>();
        for (int index = 0; index < 3; index++) observations.Add(($"benign-observation-{index}", index < successes));
        var summary = ((string Message, string Type))method!.Invoke(null, new object[] { observations })!;
        Assert.Contains(expected, summary.Message);
        Assert.Equal(expectedType, summary.Type);
    }

    private static string ReadSource(string relativePath)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current != null && !Directory.Exists(Path.Combine(current.FullName, "src"))) current = current.Parent;
        Assert.NotNull(current);
        return File.ReadAllText(Path.Combine(current!.FullName, relativePath));
    }
}
