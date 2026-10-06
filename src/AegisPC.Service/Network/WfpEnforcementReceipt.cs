using System.Net;

namespace AegisPC.Service.Network;

/// <summary>Separates native operations from requests recorded without Windows enforcement.</summary>
public enum WfpEnforcementOutcome { Applied, AlreadyApplied, RecordedOnly, Failed, Unsupported, NotFound }

/// <summary>Reports a native operation, not malware proof or evidence of a connection attempt.</summary>
public sealed record WfpEnforcementReceipt(WfpEnforcementOutcome Outcome, string Address,
    ulong? NativeFilterId, string ReasonCode, uint? NativeError = null)
{
    /// <summary>True only for a native operation; recorded requests never count as containment.</summary>
    public bool IsApplied => Outcome is WfpEnforcementOutcome.Applied or WfpEnforcementOutcome.AlreadyApplied;
}

/// <summary>Injectable native boundary; tests use inert backends, never the host firewall.</summary>
public interface IWfpNativeBackend : IDisposable
{
    /// <summary>Whether the current OS and ABI are supported independently of BFE access.</summary>
    bool IsSupported { get; }
    /// <summary>An open dynamic native session, not a subscribed telemetry source.</summary>
    bool IsAvailable { get; }
    /// <summary>Attempts an outbound address filter and returns the Windows status and ID.</summary>
    (uint Error, ulong FilterId) AddOutboundFilter(IPAddress address, string reason);
    /// <summary>Returns the actual removal status; failures must retain rollback state.</summary>
    uint DeleteFilter(ulong filterId);
}
