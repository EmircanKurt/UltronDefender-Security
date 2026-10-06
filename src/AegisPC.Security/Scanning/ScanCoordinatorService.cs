using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Policy;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning;

/// <summary>Owns one scan at a time and publishes exactly one terminal outcome for each claimed scan.</summary>
public partial class ScanCoordinatorService : IScanCoordinatorService, IBackgroundScanCoordinator
{
    private readonly IFileScanner _fileScanner;
    private readonly ISecurityFindingService _findingService;
    private readonly IQuarantineService? _quarantineService;
    private readonly IAuditLogService? _auditLogService;
    private readonly ISettingsService? _settingsService;
    private readonly IPolicyEngine? _policyEngine;
    private readonly ILogger<ScanCoordinatorService>? _logger;
    private CancellationTokenSource? _scanCts;
    private readonly object _lock = new();
    private readonly List<SecurityFinding> _currentFindings = new();
    private ScanSession? _currentSession;
    private Task<ScanResult?>? _activeScanTask;
    private Action? _externalPauseAction;
    private Action? _externalResumeAction;
    private Action? _externalCancelAction;
    private bool _isExternalScanRunning;
    private ExternalScannerSubscription? _externalRegistration;
    private readonly AsyncLocal<ExternalScannerSubscription?> _legacyExternalRegistration = new();
    private volatile ScanState _state = ScanState.Idle;
    private volatile ScanStopReason _stopReason = ScanStopReason.None;

    /// <summary>Indicates that an identity-bound external scanner currently owns the coordinator.</summary>
    public bool IsExternalScanRunning => _isExternalScanRunning;
    /// <summary>The active or terminal lifecycle state of the most recently claimed scan.</summary>
    public ScanState State => _state;
    /// <summary>The lifecycle reason of the most recent stop request or terminal result.</summary>
    public ScanStopReason StopReason => _stopReason;
    /// <summary>True while a scan is running, paused, or awaiting cancellation cleanup.</summary>
    public bool IsScanning => _state is ScanState.Scanning or ScanState.Paused or ScanState.Cancelling;
    /// <summary>The mode of the scan that owns or most recently owned the coordinator.</summary>
    public ScanType CurrentScanType { get; private set; } = ScanType.Quick;
    /// <summary>The last observed progress; only a completed result sets it to 100.</summary>
    public double ProgressPercent { get; private set; }
    /// <summary>The current inspection target or terminal display label.</summary>
    public string CurrentFile { get; private set; } = string.Empty;
    /// <summary>The analyzed file count from the current or terminal scan result.</summary>
    public int ScannedFiles { get; private set; }
    /// <summary>The discovered candidate count from the current or terminal scan result.</summary>
    public int TotalFiles { get; private set; }
    /// <summary>The number of findings retained with the current or terminal result.</summary>
    public int FindingsCount { get { lock (_lock) return _currentFindings.Count; } }
    /// <summary>A localized display summary of the scan lifecycle, excluding raw exception messages.</summary>
    public string StatusText { get; private set; } = "Taramaya hazır.";
    /// <summary>The scan duration most recently reported by the scanner.</summary>
    public TimeSpan ElapsedTime { get; private set; } = TimeSpan.Zero;
    /// <summary>The identity-bound owned session; null after its terminal notification finishes.</summary>
    public IScanSession? CurrentSession { get { lock (_lock) return _currentSession; } }
    /// <summary>A detached list of the findings retained for the current scan outcome.</summary>
    public IReadOnlyList<SecurityFinding> CurrentFindings { get { lock (_lock) return _currentFindings.ToList(); } }
    /// <summary>Notifies each observer of a claimed session; observer exceptions cannot stop the scanner.</summary>
    public event Action<IScanSession>? ScanSessionStarted;
    /// <summary>Notifies each observer of accepted progress; observer exceptions are isolated.</summary>
    public event Action<ScanProgress>? ProgressChanged;
    /// <summary>Publishes a scan's single terminal result, including failed and cancelled scans.</summary>
    public event Action<ScanResult>? ScanCompleted;

    /// <summary>Configures the scanner and optional finding policy without starting any inspection.</summary>
    public ScanCoordinatorService(IFileScanner fileScanner, ISecurityFindingService findingService,
        IQuarantineService? quarantineService = null, IAuditLogService? auditLogService = null,
        ISettingsService? settingsService = null, IPolicyEngine? policyEngine = null,
        ILogger<ScanCoordinatorService>? logger = null)
    {
        _fileScanner = fileScanner;
        _findingService = findingService;
        _quarantineService = quarantineService;
        _auditLogService = auditLogService;
        _settingsService = settingsService;
        _policyEngine = policyEngine;
        _logger = logger;
    }

    /// <summary>Starts a manual scan or returns the active manual task; an external owner returns null.</summary>
    public Task<ScanResult?> StartScanAsync(ScanType scanType, string customPath = "") =>
        StartOwnedScan(scanType, customPath, CancellationToken.None, background: false);

    /// <summary>Claims a manual scan before applying its profile; a busy owner returns null without invoking the callback.</summary>
    public Task<ScanResult?> TryStartManualScanAsync(ScanType scanType, string customPath, Action beforeOwnedScanStarts)
    {
        ArgumentNullException.ThrowIfNull(beforeOwnedScanStarts);
        return StartOwnedScan(scanType, customPath, CancellationToken.None, background: true, beforeOwnedScanStarts);
    }

    /// <summary>Atomically claims an idle coordinator and binds cancellation to that scan only.</summary>
    public Task<ScanResult?> TryStartBackgroundScanAsync(ScanType scanType, CancellationToken cancellationToken) =>
        StartOwnedScan(scanType, string.Empty, cancellationToken, background: true);

    /// <summary>Applies an owned profile only when no manual or external scan is active.</summary>
    public Task<ScanResult?> TryStartBackgroundScanAsync(ScanType scanType, CancellationToken cancellationToken,
        Action beforeOwnedScanStarts) =>
        StartOwnedScan(scanType, string.Empty, cancellationToken, background: true, beforeOwnedScanStarts);

    private Task<ScanResult?> StartOwnedScan(ScanType scanType, string customPath,
        CancellationToken cancellationToken, bool background, Action? beforeOwnedScanStarts = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ScanSession session;
        TaskCompletionSource<ScanResult?> completion;
        lock (_lock)
        {
            if (_activeScanTask != null && !_activeScanTask.IsCompleted)
                return background ? Task.FromResult<ScanResult?>(null) : _activeScanTask;
            if (_isExternalScanRunning) return Task.FromResult<ScanResult?>(null);
            ResetScanDisplay(scanType, "Tarama başlatılıyor...", $"{scanType} taraması çalışıyor...");
            _scanCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            session = new ScanSession(scanType, customPath, _scanCts, () => { }, () => { }, () => { });
            _currentSession = session;
            session.SetOwnerActions(() => ApplyToOwnedSession(session.SessionId, PauseScan),
                () => ApplyToOwnedSession(session.SessionId, ResumeScan),
                () => ApplyToOwnedSession(session.SessionId, CancelScan));
            completion = new TaskCompletionSource<ScanResult?>(TaskCreationOptions.RunContinuationsAsynchronously);
            _activeScanTask = completion.Task;
        }

        try { beforeOwnedScanStarts?.Invoke(); }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to prepare owned scan {ScanId}.", session.SessionId);
            var result = CreateInterruptedResult(session, session.CancellationToken.IsCancellationRequested
                ? ScanStatus.Cancelled : ScanStatus.Failed);
            if (result.Status == ScanStatus.Failed)
                result.FailureInfo = CreateFailure(session.SessionId, ScanFailureStage.Preparation, ex);
            PublishOwnedOutcome(session, result);
            completion.TrySetResult(result);
            return completion.Task;
        }

        NotifyObservers(ScanSessionStarted, (IScanSession)session, nameof(ScanSessionStarted));
        _ = CompleteOwnedScanAsync(session, completion);
        return completion.Task;
    }

    private void ResetScanDisplay(ScanType scanType, string currentFile, string status)
    {
        _state = ScanState.Scanning;
        _stopReason = ScanStopReason.None;
        CurrentScanType = scanType;
        ProgressPercent = 0;
        CurrentFile = currentFile;
        ScannedFiles = 0;
        TotalFiles = 0;
        ElapsedTime = TimeSpan.Zero;
        _currentFindings.Clear();
        StatusText = status;
    }

    private void ApplyToOwnedSession(Guid sessionId, Action action)
    {
        lock (_lock)
        {
            if (_currentSession?.SessionId == sessionId && _currentSession.IsActive) action();
        }
    }

    /// <summary>Indicates an owned pause without treating a stale scanner pause as a new active scan.</summary>
    public bool IsPaused
    {
        get { lock (_lock) return _state == ScanState.Paused || (_state == ScanState.Scanning && _fileScanner.IsPaused); }
    }

    /// <summary>Pauses the current owner's scanner and retains its ownership until terminal cleanup.</summary>
    public void PauseScan()
    {
        Action? external;
        lock (_lock)
        {
            if (_state != ScanState.Scanning) return;
            if (_externalRegistration == null) _fileScanner.PauseScan();
            external = _externalPauseAction;
            _state = ScanState.Paused;
            StatusText = "Tarama duraklatıldı.";
        }
        InvokeExternalAction(external, "pause");
    }

    /// <summary>Resumes only the current owned scanner or its registered external delegate.</summary>
    public void ResumeScan()
    {
        Action? external;
        lock (_lock)
        {
            if (_state != ScanState.Paused) return;
            if (_externalRegistration == null && _fileScanner.IsPaused) _fileScanner.ResumeScan();
            external = _externalResumeAction;
            _state = ScanState.Scanning;
            StatusText = $"{CurrentScanType} taraması çalışıyor...";
        }
        InvokeExternalAction(external, "resume");
    }

    /// <summary>Requests cancellation of the current owner, even if resuming a paused scanner fails.</summary>
    public void CancelScan()
    {
        Action? external;
        lock (_lock)
        {
            if (_state is not (ScanState.Scanning or ScanState.Paused)) return;
            _state = ScanState.Cancelling;
            _stopReason = ScanStopReason.UserCancelled;
            StatusText = "Tarama iptal ediliyor...";
            if (_externalRegistration == null) ResumeScannerForCleanup();
            try { _scanCts?.Cancel(); }
            catch (Exception ex) { _logger?.LogWarning(ex, "Owned scan cancellation callbacks failed."); }
            external = _externalCancelAction;
        }
        InvokeExternalAction(external, "cancel");
    }

    private void InvokeExternalAction(Action? action, string operation)
    {
        try { action?.Invoke(); }
        catch (Exception ex) { _logger?.LogWarning(ex, "External scanner {Operation} callback failed.", operation); }
    }

    private void NotifyObservers<T>(Action<T>? observers, T value, string eventName)
    {
        if (observers == null) return;
        foreach (Action<T> observer in observers.GetInvocationList())
        {
            try { observer(value); }
            catch (Exception ex) { _logger?.LogWarning(ex, "Scan observer failed while handling {EventName}.", eventName); }
        }
    }
}
