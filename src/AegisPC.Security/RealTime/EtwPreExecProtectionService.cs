using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime;

/// <summary>
/// Bounded ETW post-start inspection. The compatibility name does not imply a pre-execution gate:
/// ETW delivery is asynchronous, can lose events, and cannot prevent the first instruction.
/// Unconfirmed or incomplete analysis never suspends or terminates a process.
/// </summary>
public sealed class EtwPreExecProtectionService : IEtwPreExecProtectionService
{
    private readonly IDetectionHub _detectionHub;
    private readonly IScanCacheService? _scanCacheService;
    private readonly IQuarantineService? _quarantineService;
    private readonly IAuditLogService? _auditLogService;
    private readonly IExclusionService? _exclusionService;
    private readonly ILogger<EtwPreExecProtectionService>? _logger;
    private readonly Func<bool> _enableAutoQuarantine;
    private readonly Func<int> _autoQuarantineThreshold;
    private readonly object _lock = new();
    private readonly string _sessionName = $"UltronDefender_PostStart_{Environment.ProcessId}_{Guid.NewGuid():N}";
    private TraceEventSession? _session;
    private CancellationTokenSource? _cts;
    private Channel<ProcessArrival>? _arrivals;
    private Task? _processingTask;
    private Task[] _workers = Array.Empty<Task>();
    private volatile bool _isRunning;
    private volatile bool _isEtwSubscribed;
    private long _droppedEvents;
    private long _operatingSystemLostEvents;
    private Timer? _lossMonitor;

    /// <summary>Microsoft's kernel-process ETW provider; not a process creation veto callback.</summary>
    public static readonly Guid KernelProcessProviderGuid = new("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
    /// <summary>Whether this observer has been started, including degraded non-ETW operation.</summary>
    public bool IsRunning => _isRunning;
    /// <summary>Whether the trace-consumer loop is currently subscribed.</summary>
    public bool IsEtwSubscribed => _isEtwSubscribed;
    /// <summary>Maximum cooperative inspection duration; no process is suspended while waiting.</summary>
    public TimeSpan ScanTimeout { get; set; } = TimeSpan.FromSeconds(3);
    /// <summary>Lost managed-queue arrivals; operating-system ETW loss remains a separate limitation.</summary>
    public long DroppedEventsCount => Interlocked.Read(ref _droppedEvents);
    /// <summary>Kernel trace events reported lost across this observer's sessions; missing contents cannot be recovered.</summary>
    public long OperatingSystemLostEvents => Interlocked.Read(ref _operatingSystemLostEvents);
    /// <summary>Raised only after an actual confirmed-threat quarantine succeeds.</summary>
    public event Action<PreExecThreatAlert>? OnThreatBlocked;

    /// <summary>Creates a post-start observer without altering the OS or starting a trace session.</summary>
    public EtwPreExecProtectionService(IDetectionHub detectionHub, IRiskScoringEngine riskScoringEngine,
        ISignatureVerifier signatureVerifier, IScanCacheService? scanCacheService = null,
        IQuarantineService? quarantineService = null, IAuditLogService? auditLogService = null,
        ILogger<EtwPreExecProtectionService>? logger = null, IExclusionService? exclusionService = null,
        Func<bool>? enableAutoQuarantine = null, Func<int>? autoQuarantineThreshold = null)
    {
        _detectionHub = detectionHub ?? throw new ArgumentNullException(nameof(detectionHub));
        ArgumentNullException.ThrowIfNull(riskScoringEngine);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        _scanCacheService = scanCacheService;
        _quarantineService = quarantineService;
        _auditLogService = auditLogService;
        _logger = logger;
        _exclusionService = exclusionService;
        _enableAutoQuarantine = enableAutoQuarantine ?? (() => true);
        _autoQuarantineThreshold = autoQuarantineThreshold ?? (() => 85);
    }

    /// <summary>Starts this instance's own trace and two bounded consumers; never stops another trace.</summary>
    public void Start()
    {
        lock (_lock)
        {
            if (_isRunning) return;
            _isRunning = true;
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _arrivals = Channel.CreateBounded<ProcessArrival>(new BoundedChannelOptions(256)
            { FullMode = BoundedChannelFullMode.Wait, SingleWriter = true, SingleReader = false });
            var arrivals = _arrivals;
            _workers = new[] { Task.Run(() => ConsumeAsync(arrivals, token)), Task.Run(() => ConsumeAsync(arrivals, token)) };
            try
            {
                var session = new TraceEventSession(_sessionName, TraceEventSessionOptions.Create);
                _session = session;
                session.Source.Dynamic.All += OnKernelProcessEvent;
                session.EnableProvider(KernelProcessProviderGuid, TraceEventLevel.Informational, matchAnyKeywords: 0x10 | 0x40);
                _isEtwSubscribed = true;
                int lastObservedLoss = 0;
                _lossMonitor = new Timer(_ =>
                {
                    if (token.IsCancellationRequested) return;
                    try
                    {
                        int lost = session.EventsLost;
                        int previous = Interlocked.Exchange(ref lastObservedLoss, lost);
                        if (lost > previous)
                        {
                            Interlocked.Add(ref _operatingSystemLostEvents, lost - previous);
                            _logger?.LogWarning("ETW reported {Lost} operating-system events lost; post-start coverage is incomplete", lost);
                        }
                    }
                    catch (Exception ex) { _logger?.LogDebug(ex, "Could not query ETW session loss statistics"); }
                }, null, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3));
                _processingTask = Task.Factory.StartNew(() =>
                {
                    try { session.Source.Process(); }
                    catch (Exception ex) when (!token.IsCancellationRequested)
                    { _logger?.LogError(ex, "ETW consumer stopped unexpectedly; post-start coverage is degraded"); }
                    catch (Exception ex) { _logger?.LogDebug(ex, "ETW consumer ended during shutdown"); }
                    finally { if (!token.IsCancellationRequested) _isEtwSubscribed = false; }
                }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
                _logger?.LogInformation("ETW post-start monitoring subscribed; execution before delivery is not intercepted");
            }
            catch (Exception ex)
            {
                _isEtwSubscribed = false;
                _session?.Dispose();
                _session = null;
                _logger?.LogWarning(ex, "ETW unavailable. File arrival monitoring must remain enabled independently");
            }
        }
    }

    /// <summary>Stops this trace and cancels queued work without disabling independent file monitoring.</summary>
    public void Stop()
    {
        CancellationTokenSource? cancellation;
        Task[] pending;
        lock (_lock)
        {
            if (!_isRunning) return;
            _isRunning = false;
            _isEtwSubscribed = false;
            _lossMonitor?.Dispose();
            _lossMonitor = null;
            cancellation = _cts;
            _cts = null;
            cancellation?.Cancel();
            _arrivals?.Writer.TryComplete();
            _arrivals = null;
            pending = _processingTask == null ? _workers : _workers.Append(_processingTask).ToArray();
            _workers = Array.Empty<Task>();
            _processingTask = null;
            try { _session?.Stop(); _session?.Dispose(); }
            catch (Exception ex) { _logger?.LogWarning(ex, "Failed to stop owned ETW session"); }
            finally { _session = null; }
        }
        _ = Task.WhenAll(pending).ContinueWith(task =>
        {
            if (task.IsFaulted) _logger?.LogError(task.Exception, "ETW shutdown task failed");
            cancellation?.Dispose();
        }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private void OnKernelProcessEvent(TraceEvent data)
    {
        if (!_isRunning) return;
        try
        {
            bool processStart = data.EventName.Contains("ProcessStart", StringComparison.OrdinalIgnoreCase) ||
                (data.EventName.Contains("Process", StringComparison.OrdinalIgnoreCase) && data.EventName.EndsWith("/Start", StringComparison.OrdinalIgnoreCase));
            bool imageLoad = data.EventName.Contains("ImageLoad", StringComparison.OrdinalIgnoreCase) ||
                (data.EventName.Contains("Image", StringComparison.OrdinalIgnoreCase) && data.EventName.EndsWith("/Load", StringComparison.OrdinalIgnoreCase));
            if (!processStart && !imageLoad) return;
            int pid = data.ProcessID;
            var names = data.PayloadNames;
            if (names.Contains("ProcessID", StringComparer.OrdinalIgnoreCase) &&
                int.TryParse(data.PayloadByName("ProcessID")?.ToString(), out int eventPid)) pid = eventPid;
            if (pid <= 4 || pid == Environment.ProcessId) return;
            var imageField = names.FirstOrDefault(name => name.Equals("ImageFileName", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("FileName", StringComparison.OrdinalIgnoreCase) || name.Equals("ImageName", StringComparison.OrdinalIgnoreCase));
            string? image = imageField == null ? null : data.PayloadByName(imageField)?.ToString();
            if (string.IsNullOrWhiteSpace(image)) return;
            if (_arrivals?.Writer.TryWrite(new ProcessArrival(pid, image)) != true)
            {
                long lost = Interlocked.Increment(ref _droppedEvents);
                if (lost == 1 || lost % 100 == 0)
                    _logger?.LogWarning("ETW post-start queue saturation; {Count} events lost. Coverage is incomplete", lost);
            }
        }
        catch (Exception ex) { _logger?.LogWarning(ex, "Could not normalize kernel process event"); }
    }

    private async Task ConsumeAsync(Channel<ProcessArrival> arrivals, CancellationToken token)
    {
        try
        {
            await foreach (var arrival in arrivals.Reader.ReadAllAsync(token))
            {
                try { await EvaluateProcessAsync(arrival.ProcessId, arrival.ImagePath, ct: token); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger?.LogWarning(ex, "Post-start inspection failed for PID {Pid}", arrival.ProcessId); }
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }

    /// <summary>
    /// Inspects a stable, hash-bound image after process start. Only exact signature evidence can
    /// request quarantine; PID and executable identity are independently checked before containment.
    /// Missing files, detector failures and timeout produce unverified decisions, never clean claims.
    /// </summary>
    public async Task<PreExecDecision> EvaluateProcessAsync(int processId, string imagePath, string commandLine = "", CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var decision = new PreExecDecision { ProcessId = processId, ImagePath = imagePath };
        if (processId <= 4 || processId == Environment.ProcessId)
        {
            decision.Whitelisted = true;
            decision.Reason = "System or self PID; containment is prohibited";
            return decision;
        }
        if (string.IsNullOrWhiteSpace(imagePath) || !File.Exists(imagePath))
        {
            decision.Reason = "Image unavailable; inspection is incomplete";
            return decision;
        }
        if (ScanTimeout <= TimeSpan.Zero || ScanTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(ScanTimeout));
        using var timeout = new CancellationTokenSource(ScanTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
        Process? identity = null;
        DateTime? processStart = null;
        string? processImage = null;
        try
        {
            try
            {
                identity = Process.GetProcessById(processId);
                _ = identity.Handle;
                processStart = identity.StartTime.ToUniversalTime();
                processImage = identity.MainModule?.FileName;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                _logger?.LogDebug(ex, "No verifiable process identity for PID {Pid}; file-only inspection continues", processId);
                identity?.Dispose();
                identity = null;
            }
            string sha256;
            DetectionResult detection;
            using (var source = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                sha256 = Convert.ToHexString(await SHA256.HashDataAsync(source, linked.Token));
                var info = new FileInfo(imagePath);
                if (_exclusionService?.IsExcluded(imagePath, sha256) == true)
                {
                    decision.Whitelisted = true;
                    decision.Reason = "Explicit user exclusion matched verified image content";
                    return decision;
                }
                if (_scanCacheService != null)
                {
                    var cached = await _scanCacheService.TryGetVerdictAsync(imagePath, sha256, source.Length, info.LastWriteTimeUtc, linked.Token);
                    if (cached?.Verdict == RealTimeVerdict.Clean && string.Equals(cached.SHA256, sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        decision.CacheHit = true;
                        // This legacy cache has no rules/feed version. A hash proves file identity,
                        // not that yesterday's clean verdict remains valid against today's rules.
                        _logger?.LogDebug("Content cache hit for {Path}; refreshing unversioned detection verdict", imagePath);
                    }
                }
                detection = await _detectionHub.EvaluateAsync(new DetectionContext
                {
                    FilePath = imagePath, SHA256 = sha256, FileSize = source.Length,
                    LastWriteTimeUtc = info.LastWriteTimeUtc, ProcessId = processId,
                    IsRunningProcess = identity != null, CorrelationId = Guid.NewGuid().ToString("N")
                }, linked.Token);
                linked.Token.ThrowIfCancellationRequested();
            }
            decision.RiskScore = detection.RiskScore;
            bool confirmed = detection.Verdict == DetectionVerdict.ConfirmedMalicious && detection.Evidences.Any(e =>
                e.Category == EvidenceCategory.StaticSignature && e.Confidence == EvidenceConfidence.Absolute && e.ScoreContribution >= 80);
            if (!confirmed)
            {
                decision.Reason = !detection.IsComplete || detection.Verdict == DetectionVerdict.Unknown
                    ? "Inspection incomplete; process was not declared clean or contained"
                    : detection.RiskScore >= 50 ? "Unconfirmed heuristic risk; observation only, no process suspension"
                    : "Clean execution permitted";
                return decision;
            }
            if (!_enableAutoQuarantine() || decision.RiskScore < Math.Clamp(_autoQuarantineThreshold(), 1, 100))
            {
                decision.Reason = "Confirmed threat observed; automatic quarantine disabled by user policy";
                return decision;
            }
            // A critical name prohibits destructive containment; it never bypasses content inspection.
            bool canContain = identity != null && processStart.HasValue && !identity.HasExited &&
                identity.StartTime.ToUniversalTime() == processStart.Value &&
                !string.IsNullOrWhiteSpace(processImage) &&
                string.Equals(Path.GetFullPath(processImage), Path.GetFullPath(imagePath), StringComparison.OrdinalIgnoreCase) &&
                !CriticalProcesses.IsCriticalProcess(identity.ProcessName);
            bool quarantined = false;
            if (_quarantineService is IContentBoundQuarantineService contentBound)
                quarantined = await contentBound.TryQuarantineFileAsync(imagePath, "ETW post-start: " + detection.ThreatTitle, sha256, ct);
            // Keep one captured process identity; never kill a newly reused PID or an unrelated DLL host.
            if (quarantined && canContain && identity != null && !identity.HasExited)
            {
                try { identity.Kill(entireProcessTree: false); }
                catch (Exception ex) { _logger?.LogWarning(ex, "Confirmed image quarantined but verified process containment failed for PID {Pid}", processId); }
            }
            decision.WasBlocked = quarantined;
            decision.Reason = quarantined ? "Confirmed threat quarantined after process start" : "Confirmed threat observed; content-bound quarantine unavailable or unsuccessful";
            if (quarantined)
            {
                OnThreatBlocked?.Invoke(new PreExecThreatAlert { ProcessId = processId, ImagePath = imagePath,
                    CommandLine = commandLine, ThreatTitle = detection.ThreatTitle, RiskScore = detection.RiskScore });
                if (_auditLogService != null)
                    await _auditLogService.LogActionAsync(AuditAction.FileQuarantined, "EtwPostStartProtection",
                        Path.GetFileName(imagePath), imagePath, decision.Reason, AuditResult.Success, cancellationToken: ct);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && timeout.IsCancellationRequested)
        {
            decision.TimedOut = true;
            decision.Reason = $"Post-start inspection timeout exceeded ({ScanTimeout.TotalMilliseconds:F0}ms); no process was suspended";
            _logger?.LogWarning("ETW inspection timed out for PID {Pid}, Path {Path}", processId, imagePath);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            decision.Reason = "Inspection incomplete: " + ex.GetType().Name;
            _logger?.LogWarning(ex, "Post-start image inspection failed for {Path}", imagePath);
        }
        finally { identity?.Dispose(); }
        return decision;
    }

    /// <summary>Stops this observer without altering independent protection or other trace sessions.</summary>
    public void Dispose() => Stop();
    private sealed record ProcessArrival(int ProcessId, string ImagePath);
}
