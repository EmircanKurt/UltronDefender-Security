using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Exercises scheduled result reporting without scheduling, live protection, or persisted state.</summary>
public sealed class BackgroundNotificationRegressionTests
{
    [Fact]
    public void ResolvedAllowedAndCleanFindings_DoNotBecomeNewThreatNotifications()
    {
        var service = new BackgroundProtectionService(null!, null!, null!);
        int events = 0;
        service.OnThreatDetected += _ => events++;
        service.OnNotificationRaised += (_, _) => events++;
        service.NotifyScheduledScanCompleted(new ScanResult
        {
            Status = ScanStatus.Completed,
            Findings = new()
            {
                Finding(FindingStatus.Resolved, RiskLevel.HighRisk),
                Finding(FindingStatus.Active, RiskLevel.Clean),
                new SecurityFinding { ObjectPath = Guid.NewGuid().ToString(), IsAllowlisted = true, RiskLevel = RiskLevel.HighRisk }
            }
        });
        Assert.Equal(0, events);
    }

    [Theory]
    [InlineData(ScanStatus.Cancelled)]
    [InlineData(ScanStatus.Failed)]
    public void IncompleteScan_DoesNotReportSuccessfulDiscovery(ScanStatus status)
    {
        var service = new BackgroundProtectionService(null!, null!, null!);
        int events = 0;
        service.OnNotificationRaised += (_, _) => events++;
        service.NotifyScheduledScanCompleted(new ScanResult { Status = status, Findings = new() { Finding(FindingStatus.Active, RiskLevel.HighRisk) } });
        Assert.Equal(0, events);
    }

    [Fact]
    public void ActiveFinding_IsReportedOnceAndNotSilenced()
    {
        var service = new BackgroundProtectionService(null!, null!, null!);
        int discoveries = 0;
        int summaries = 0;
        service.OnThreatDetected += _ => discoveries++;
        service.OnNotificationRaised += (_, _) => summaries++;
        var result = new ScanResult { Status = ScanStatus.Completed, Findings = new() { Finding(FindingStatus.Active, RiskLevel.HighRisk) } };
        service.NotifyScheduledScanCompleted(result);
        service.NotifyScheduledScanCompleted(result);
        Assert.Equal(1, discoveries);
        Assert.Equal(1, summaries);
    }

    private static SecurityFinding Finding(FindingStatus status, RiskLevel risk) =>
        new() { ObjectPath = Guid.NewGuid().ToString(), Status = status, RiskLevel = risk };
}
