using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.Services;

/// <summary>Read-only UI compatibility facade. Only the protection service owns observers, canaries and containment.</summary>
public sealed class ServiceRansomwareClient : IRansomwareProtectionEngine, IDisposable
{
    private readonly IServiceIpcClient _ipc;
    private ProtectionStatus? _status;
    private bool _disposed;

    /// <summary>Subscribes to metadata only; construction never starts local protection or touches user files.</summary>
    public ServiceRansomwareClient(IServiceIpcClient ipc)
    {
        _ipc = ipc;
        _ipc.StatusChanged += ObserveStatus;
    }

    /// <inheritdoc />
    public bool IsShieldActive => !_disposed && ServiceProtectionStatusPolicy.IsVerified(_ipc, _status) && _status!.IsRansomwareShieldEnabled;
    /// <inheritdoc />
    public IReadOnlyList<string> ProtectedDirectories => Array.Empty<string>();
    /// <inheritdoc />
    public IReadOnlyList<AllowedRansomwareApplication> AllowedApplications => Array.Empty<AllowedRansomwareApplication>();
    /// <inheritdoc />
    public int CanaryFileCount => !_disposed && ServiceProtectionStatusPolicy.IsVerified(_ipc, _status) ? Math.Max(0, _status!.RansomwareCanaryFileCount ?? 0) : 0;
    /// <inheritdoc />
    public int TotalBlockedAttempts => !_disposed && ServiceProtectionStatusPolicy.IsVerified(_ipc, _status) ? Math.Max(0, _status!.RansomwareConfirmedContainments ?? 0) : 0;

    // Raw cross-user incident/list endpoints are not exposed by this compatibility contract.
    /// <inheritdoc />
    public event EventHandler<RansomwareAlertEventArgs>? OnRansomwareAttemptDetected { add { } remove { } }
    /// <inheritdoc />
    public event Action<string, string, string>? OnNotificationRaised { add { } remove { } }

    /// <inheritdoc />
    public void StartShield() => throw Unavailable();
    /// <inheritdoc />
    public void StopShield() => throw Unavailable();
    /// <inheritdoc />
    public void AddProtectedDirectory(string path) => throw Unavailable();
    /// <inheritdoc />
    public void RemoveProtectedDirectory(string path) => throw Unavailable();
    /// <inheritdoc />
    public void AddAllowedApplication(string executablePath, string? appName = null) => throw Unavailable();
    /// <inheritdoc />
    public void RemoveAllowedApplication(string executablePath) => throw Unavailable();
    /// <inheritdoc />
    public bool IsApplicationAllowed(string executablePath) => false;
    /// <inheritdoc />
    public void CleanupCanaryFiles() => throw Unavailable();
    /// <inheritdoc />
    public Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(string offendingPath, string reason, int riskScore, int pid = 0, DateTime? incidentTimestamp = null) =>
        Task.FromException<RansomwareDamageAssessment?>(Unavailable());

    private static NotSupportedException Unavailable() => new("Only authorized, acknowledged protection-service operations are permitted; local ransomware operations are unavailable.");
    private void ObserveStatus(ProtectionStatus status) { if (!_disposed) _status = status; }

    /// <summary>Removes metadata subscriptions without stopping service-owned protection.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _status = null;
        _ipc.StatusChanged -= ObserveStatus;
    }
}
