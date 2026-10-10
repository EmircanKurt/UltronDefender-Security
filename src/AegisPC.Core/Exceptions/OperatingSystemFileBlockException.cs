using System;
using System.IO;

namespace AegisPC.Core.Exceptions;

/// <summary>Reports an OS security provider's access result, not an Ultron content identity or malware-family verdict.</summary>
public enum OperatingSystemFileBlockKind { ThreatBlocked, ThreatRemoved }

/// <summary>Preserves an OS-reported block without encoding it as a fake SHA-256 or calling it EICAR.</summary>
public sealed class OperatingSystemFileBlockException : IOException
{
    /// <summary>Which documented OS access result was observed; the reporting provider/family may be unknown.</summary>
    public OperatingSystemFileBlockKind Kind { get; }

    /// <summary>Creates a typed unavailable-inspection result; an inner native exception is retained for diagnostics.</summary>
    public OperatingSystemFileBlockException(OperatingSystemFileBlockKind kind, Exception? inner = null)
        : base("A Windows security provider blocked or removed the file; Ultron inspection is unavailable.", inner)
    {
        Kind = kind;
        HResult = kind == OperatingSystemFileBlockKind.ThreatBlocked ? unchecked((int)0x800700E1) : unchecked((int)0x800700E2);
    }

    /// <summary>Recognizes only documented HRESULTs or this typed exception; message substrings are never authority.</summary>
    public static bool TryGetKind(Exception error, out OperatingSystemFileBlockKind kind)
    {
        if (error is OperatingSystemFileBlockException typed) { kind = typed.Kind; return true; }
        kind = error.HResult == unchecked((int)0x800700E2) ? OperatingSystemFileBlockKind.ThreatRemoved : OperatingSystemFileBlockKind.ThreatBlocked;
        return error is IOException && error.HResult is unchecked((int)0x800700E1) or unchecked((int)0x800700E2);
    }
}
