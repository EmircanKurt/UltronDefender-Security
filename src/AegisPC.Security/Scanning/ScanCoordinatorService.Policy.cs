using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning;

/// <summary>Applies existing finding policy only after successful scanning; failed scans retain their observations.</summary>
public partial class ScanCoordinatorService
{
    private async Task ApplyFindingPolicyAsync(ScanResult result, CancellationToken cancellationToken)
    {
        if (result.Findings.Count == 0) return;
        if (_policyEngine != null)
        {
            foreach (var finding in result.Findings)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (finding.Status == FindingStatus.Resolved || finding.IsAllowlisted) continue;
                try { await _policyEngine.EnforcePolicyAsync(finding, cancellationToken); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception ex) { _logger?.LogError(ex, "Finding policy enforcement failed."); }
            }
            return;
        }
        var autoQuarantine = _settingsService?.GetSetting("EnableAutoQuarantine", true) ?? true;
        var threshold = Math.Clamp(_settingsService?.GetSetting("AutoQuarantineThreshold", 85) ?? 85, 0, 100);
        foreach (var finding in result.Findings)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (finding.IsAllowlisted || finding.Status != FindingStatus.Active) continue;
            bool confirmed = finding.Category is FindingCategory.KnownMalwareHash or FindingCategory.ConfirmedMalicious;
            if (autoQuarantine && confirmed && finding.RiskScore >= threshold)
                await TryAutoQuarantineAsync(finding, cancellationToken);
            else if (finding.RiskScore >= 60)
                await RecordFindingAuditAsync(finding, AuditAction.ScanCompleted,
                    $"Suspicious finding observed (risk score {finding.RiskScore}); user action is pending.", cancellationToken);
        }
    }

    private async Task TryAutoQuarantineAsync(SecurityFinding finding, CancellationToken cancellationToken)
    {
        if (_quarantineService is not IContentBoundQuarantineService bound || string.IsNullOrWhiteSpace(finding.ObjectPath)) return;
        try
        {
            bool succeeded = await bound.TryQuarantineFileAsync(finding.ObjectPath,
                $"Automatic quarantine (risk score {finding.RiskScore}): {finding.Title}",
                finding.SHA256 ?? string.Empty, cancellationToken);
            if (!succeeded) return;
            finding.Status = FindingStatus.Resolved;
            await _findingService.UpdateFindingAsync(finding, cancellationToken);
            _logger?.LogInformation("An evidence-bound scan finding was automatically quarantined.");
            await RecordFindingAuditAsync(finding, AuditAction.FileQuarantined,
                $"Automatic quarantine completed (risk score {finding.RiskScore}).", cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { _logger?.LogError(ex, "Automatic quarantine of a scan finding failed."); }
    }

    private async Task RecordFindingAuditAsync(SecurityFinding finding, AuditAction action,
        string details, CancellationToken cancellationToken)
    {
        if (_auditLogService == null) return;
        try
        {
            await _auditLogService.LogActionAsync(action, "File", finding.Title,
                finding.ObjectPath, details, AuditResult.Success, null, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { _logger?.LogWarning(ex, "Recording scan finding audit metadata failed."); }
    }
}
