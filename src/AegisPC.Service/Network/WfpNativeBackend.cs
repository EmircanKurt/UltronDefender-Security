using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Network;

/// <summary>Native x64 IPv4 adapter. Inbound RDP and IPv6 enforcement are not claimed by this first-stage backend.</summary>
internal sealed class WfpNativeBackend : IWfpNativeBackend
{
    private readonly ILogger? _logger;
    private IntPtr _engine;
    /// <inheritdoc />
    public bool IsSupported => OperatingSystem.IsWindows() && Environment.Is64BitProcess;
    /// <inheritdoc />
    public bool IsAvailable => _engine != IntPtr.Zero;

    internal WfpNativeBackend(ILogger? logger)
    {
        _logger = logger;
        if (!IsSupported) return;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return;
            var session = new Session { Flags = 1, WaitMilliseconds = 5000,
                Display = new() { Name = "Ultron dynamic outbound session", Description = "Owned, nonpersistent filters" } };
            uint error = EngineOpen(null, 10, IntPtr.Zero, ref session, out _engine);
            if (error != 0) { _engine = IntPtr.Zero; _logger?.LogWarning("WFP session unavailable: {Error}", error); }
        }
        catch (Exception ex) { _engine = IntPtr.Zero; _logger?.LogWarning(ex, "WFP native session initialization failed"); }
    }

    /// <inheritdoc />
    public (uint Error, ulong FilterId) AddOutboundFilter(IPAddress address, string reason)
    {
        if (!IsAvailable) return (6, 0);
        byte[] bytes = address.GetAddressBytes();
        var condition = new Condition
        {
            Field = new Guid("b235ae9a-1d9c-44c8-a4fe-92176e01a88b"),
            Value = new Value { Type = 4, UInt32 = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3] }
        };
        IntPtr pointer = Marshal.AllocHGlobal(Marshal.SizeOf<Condition>());
        try
        {
            Marshal.StructureToPtr(condition, pointer, false);
            var filter = new Filter
            {
                Key = Guid.NewGuid(), Display = new() { Name = $"Ultron outbound {address}", Description = reason },
                Layer = new Guid("c38d57d1-05a7-4c33-904f-7fb4e73d6efb"),
                Action = new ActionValue { Type = 0x1001 }, ConditionCount = 1, Conditions = pointer,
                Weight = new Value { Type = 0 } // FWP_EMPTY: valid automatic weight, not FWP_UINT32.
            };
            uint error = FilterAdd(_engine, ref filter, IntPtr.Zero, out ulong id);
            return (error, id);
        }
        finally { Marshal.FreeHGlobal(pointer); }
    }

    /// <inheritdoc />
    public uint DeleteFilter(ulong filterId) => IsAvailable ? FilterDelete(_engine, filterId) : 6;
    /// <inheritdoc />
    public void Dispose()
    {
        if (_engine == IntPtr.Zero) return;
        uint error = EngineClose(_engine);
        if (error != 0) throw new InvalidOperationException($"WFP session close failed: {error}");
        _engine = IntPtr.Zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Display { [MarshalAs(UnmanagedType.LPWStr)] public string? Name; [MarshalAs(UnmanagedType.LPWStr)] public string? Description; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Session { public Guid Key; public Display Display; public uint Flags; public uint WaitMilliseconds; public uint ProcessId; public IntPtr Sid; public IntPtr Username; public int KernelMode; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Blob { public uint Size; public IntPtr Data; }
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct Value { [FieldOffset(0)] public uint Type; [FieldOffset(8)] public uint UInt32; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ActionValue { public uint Type; public Guid Callout; }
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct Context { [FieldOffset(0)] public ulong Raw; [FieldOffset(0)] public Guid Provider; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Filter
    {
        public Guid Key; public Display Display; public uint Flags; public IntPtr ProviderKey; public Blob ProviderData;
        public Guid Layer; public Guid Sublayer; public Value Weight; public uint ConditionCount; public IntPtr Conditions;
        public ActionValue Action; public Context Context; public IntPtr Reserved; public ulong Id; public Value EffectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Condition { public Guid Field; public uint MatchType; public Value Value; }
    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineOpen0", CharSet = CharSet.Unicode)]
    private static extern uint EngineOpen(string? server, uint authentication, IntPtr identity, ref Session session, out IntPtr engine);
    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineClose0")]
    private static extern uint EngineClose(IntPtr engine);
    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterAdd0")]
    private static extern uint FilterAdd(IntPtr engine, ref Filter filter, IntPtr descriptor, out ulong id);
    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterDeleteById0")]
    private static extern uint FilterDelete(IntPtr engine, ulong id);
}
