using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Network;

/// <summary>Reports actual outbound filter operations. Callers must separately authorize containment.</summary>
public interface IWfpEnforcementService : IDisposable
{
    /// <summary>Native session availability, not an active flow observation pipeline.</summary>
    bool IsWfpAvailable { get; }
    /// <summary>Counts only nonzero native IDs, never in-memory requests.</summary>
    int ActiveBlockFilterCount { get; }
    /// <summary>Compatibility API; true means native installation, not recorded-only fallback.</summary>
    bool BlockOutboundIp(string ipAddress, string reason = "Authorized outbound containment");
    /// <summary>True only after removal of an actual installed filter.</summary>
    bool UnblockIp(string ipAddress);
    /// <summary>Separates installed, recorded-only, failed and unsupported operations.</summary>
    WfpEnforcementReceipt BlockOutboundIpWithReceipt(string ipAddress, string reason = "Authorized outbound containment");
    /// <summary>Retains failed native removals for retry.</summary>
    WfpEnforcementReceipt UnblockIpWithReceipt(string ipAddress);
    /// <summary>Removes owned filters only; failed removals remain tracked.</summary>
    void ClearDynamicFilters();
}

/// <summary>Bounded dynamic WFP bookkeeping; this component is not an action authorization broker.</summary>
public sealed class WfpEnforcementService : IWfpEnforcementService
{
    private const int MaximumFilters = 1024;
    private const int MaximumRecordedRequests = 256;
    private readonly IWfpNativeBackend _backend;
    private readonly ILogger<WfpEnforcementService>? _logger;
    private readonly Dictionary<string, ulong> _activeFilters = new(StringComparer.Ordinal);
    private readonly HashSet<string> _recordedRequests = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private bool _disposed;

    /// <summary>Opens a dynamic session when supported; a session alone does not install filters.</summary>
    public WfpEnforcementService(ILogger<WfpEnforcementService>? logger = null)
        : this(new WfpNativeBackend(logger), logger) { }

    /// <summary>Uses an inert native boundary for deterministic testing without host firewall mutation.</summary>
    public WfpEnforcementService(IWfpNativeBackend backend, ILogger<WfpEnforcementService>? logger = null)
    { _backend = backend ?? throw new ArgumentNullException(nameof(backend)); _logger = logger; }

    /// <inheritdoc/>
    public bool IsWfpAvailable { get { lock (_gate) return !_disposed && _backend.IsAvailable; } }
    /// <inheritdoc/>
    public int ActiveBlockFilterCount { get { lock (_gate) return _activeFilters.Count; } }
    /// <summary>Counts bounded diagnostic requests that did not create native filters.</summary>
    public int RecordedRequestCount { get { lock (_gate) return _recordedRequests.Count; } }
    /// <inheritdoc/>
    public bool BlockOutboundIp(string ipAddress, string reason = "Authorized outbound containment")
        => BlockOutboundIpWithReceipt(ipAddress, reason).IsApplied;
    /// <inheritdoc/>
    public bool UnblockIp(string ipAddress) => UnblockIpWithReceipt(ipAddress).IsApplied;

    /// <inheritdoc/>
    public WfpEnforcementReceipt BlockOutboundIpWithReceipt(string ipAddress, string reason = "Authorized outbound containment")
    {
        if (!TryAddress(ipAddress, out var address)) return Receipt(WfpEnforcementOutcome.Failed, ipAddress, "InvalidAddress");
        string key = address.ToString();
        lock (_gate)
        {
            if (_disposed) return Receipt(WfpEnforcementOutcome.Failed, key, "Disposed");
            if (!_backend.IsSupported || address.AddressFamily != AddressFamily.InterNetwork)
                return Receipt(WfpEnforcementOutcome.Unsupported, key, "NativeAddressFamilyUnsupported");
            if (_activeFilters.TryGetValue(key, out ulong existing))
                return new(WfpEnforcementOutcome.AlreadyApplied, key, existing, "OwnedNativeFilterExists");
            if (!_backend.IsAvailable)
            {
                if (_recordedRequests.Count < MaximumRecordedRequests) _recordedRequests.Add(key);
                _logger?.LogInformation("Outbound request recorded without native enforcement for {Address}", key);
                return Receipt(WfpEnforcementOutcome.RecordedOnly, key, "NativeSessionUnavailable");
            }
            if (_activeFilters.Count >= MaximumFilters) return Receipt(WfpEnforcementOutcome.Failed, key, "FilterCapacityReached");
            try
            {
                string description = string.IsNullOrWhiteSpace(reason) ? "Authorized outbound containment" : reason[..Math.Min(reason.Length, 512)];
                var native = _backend.AddOutboundFilter(address, description);
                if (native.Error != 0 || native.FilterId == 0)
                    return new(WfpEnforcementOutcome.Failed, key, null, "NativeAddFailed", native.Error);
                _activeFilters.Add(key, native.FilterId);
                _recordedRequests.Remove(key);
                return new(WfpEnforcementOutcome.Applied, key, native.FilterId, "NativeFilterInstalled");
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Native outbound filter installation failed for {Address}", key);
                return Receipt(WfpEnforcementOutcome.Failed, key, "NativeAddFault");
            }
        }
    }

    /// <inheritdoc/>
    public WfpEnforcementReceipt UnblockIpWithReceipt(string ipAddress)
    {
        if (!TryAddress(ipAddress, out var address)) return Receipt(WfpEnforcementOutcome.Failed, ipAddress, "InvalidAddress");
        string key = address.ToString();
        lock (_gate)
        {
            if (_disposed) return Receipt(WfpEnforcementOutcome.Failed, key, "Disposed");
            if (!_activeFilters.TryGetValue(key, out ulong id))
            {
                if (_recordedRequests.Remove(key)) return Receipt(WfpEnforcementOutcome.RecordedOnly, key, "RecordedRequestRemoved");
                return Receipt(WfpEnforcementOutcome.NotFound, key, "NoOwnedNativeFilter");
            }
            if (!_backend.IsAvailable) return new(WfpEnforcementOutcome.Failed, key, id, "RemovalSessionUnavailable");
            try
            {
                uint error = _backend.DeleteFilter(id);
                if (error != 0) return new(WfpEnforcementOutcome.Failed, key, id, "NativeRemoveFailed", error);
                _activeFilters.Remove(key);
                return new(WfpEnforcementOutcome.Applied, key, id, "NativeFilterRemoved");
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Native filter removal failed for {Address}", key);
                return new(WfpEnforcementOutcome.Failed, key, id, "NativeRemoveFault");
            }
        }
    }

    /// <inheritdoc/>
    public void ClearDynamicFilters()
    {
        lock (_gate)
        {
            foreach (string address in _activeFilters.Keys.ToArray())
            {
                var result = UnblockIpWithReceipt(address);
                if (!result.IsApplied) _logger?.LogWarning("Owned filter cleanup incomplete: {Reason}", result.ReasonCode);
            }
            _recordedRequests.Clear();
        }
    }

    /// <summary>Closes only this dynamic session; does not remove another product's rules or disable adapters.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            ClearDynamicFilters();
            _backend.Dispose(); // A successfully closed dynamic session removes its remaining filters.
            _activeFilters.Clear();
            _disposed = true;
        }
    }

    private static bool TryAddress(string? value, out IPAddress address)
    {
        if (IPAddress.TryParse(value, out var parsed)) { address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed; return true; }
        address = IPAddress.None; return false;
    }
    private static WfpEnforcementReceipt Receipt(WfpEnforcementOutcome outcome, string address, string reason)
        => new(outcome, address, null, reason);
}
