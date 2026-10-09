using System;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using AegisPC.Core.Enums;
using AegisPC.App.ViewModels;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Inert presentation regressions; these tests perform no quarantine or OS mutation.</summary>
public sealed class FindingPresentationSafetyReviewTests
{
    /// <summary>A static file cannot invent actor identity, malware likelihood or a containment receipt.</summary>
    [Fact]
    public void LegacyFileObservation_RequiresReinspectionAndDoesNotInventActor()
    {
        var incident = FindingIncidentProjection.Create(new SecurityFinding { ObjectPath = @"C:\Windows\System32\ordinary.dll", RiskScore = 60 });
        Assert.Equal("İlişkilendirilmedi", incident.RootProcessName);
        Assert.Equal("İlişkilendirilmedi", incident.ActorPidDisplay);
        Assert.Equal("ObservationOnly", incident.Status);
        Assert.Contains("Eski kural", incident.HumanExplanation);
        Assert.Contains("kısmi", incident.HumanExplanation);
        Assert.Equal(0, Assert.Single(incident.Evidences).Confidence);
    }

    /// <summary>Review/allowlist state does not represent a successful native action.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReviewedState_IsNotRemediation(bool allowlisted)
    {
        var incident = FindingIncidentProjection.Create(new SecurityFinding { IsAllowlisted = allowlisted, Status = FindingStatus.Resolved });
        Assert.Equal("Reviewed", incident.Status);
        Assert.Contains("makbuzu yok", incident.ActionTaken);
    }

    /// <summary>A current partial inspection retains its gaps separately from score.</summary>
    [Fact]
    public void CurrentPartialObservation_PreservesProvenanceAndCoverage()
    {
        var incident = FindingIncidentProjection.Create(new SecurityFinding { RuleSetVersion = DetectionRuleSet.Version, CoverageLimitations = new() { "SignatureVerificationUnavailable" } });
        Assert.Contains(DetectionRuleSet.Version, incident.HumanExplanation);
        Assert.Contains("SignatureVerificationUnavailable", incident.HumanExplanation);
        Assert.DoesNotContain("Eski kural", incident.HumanExplanation);
    }

    /// <summary>A missing vault facade is unavailable, not an empty successfully loaded vault.</summary>
    [Fact]
    public async Task MissingVaultOwner_IsNotDisplayedAsEmpty()
    {
        var model = new QuarantineViewModel();
        await model.LoadItemsAsync();
        Assert.False(model.HasNoQuarantinedItems);
        Assert.False(model.CanRemoveAll);
        Assert.Equal("Kullanılamıyor", model.VaultCountText);
    }
}
