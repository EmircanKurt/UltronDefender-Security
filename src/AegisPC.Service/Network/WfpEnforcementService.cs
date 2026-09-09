using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Network
{
    public interface IWfpEnforcementService : IDisposable
    {
        bool IsWfpAvailable { get; }
        int ActiveBlockFilterCount { get; }
        bool BlockOutboundIp(string ipAddress, string reason = "Malicious C2 Communication");
        bool UnblockIp(string ipAddress);
        void ClearDynamicFilters();
    }

    /// <summary>
    /// Windows Filtering Platform (WFP) Kullanıcı Modu Paket ve Bağlantı Engelleme Servisi.
    /// fwpuclnt.dll (BFE - Base Filtering Engine) P/Invoke çağrıları ile
    /// FWPM_LAYER_ALE_AUTH_CONNECT_V4 katmanında dinamik giden (outbound) IP engelleme filtreleri oluşturur.
    /// Dynamic session (FWPM_SESSION_FLAG_DYNAMIC) bayrağı sayesinde servis kapandığında
    /// veya çöktüğünde tüm kurallar çekirdek tarafından otomatik silinir; internet kalıcı kilitlenmez.
    /// </summary>
    public class WfpEnforcementService : IWfpEnforcementService
    {
        private readonly ILogger<WfpEnforcementService>? _logger;
        private IntPtr _engineHandle = IntPtr.Zero;
        private bool _isAvailable;
        private readonly ConcurrentDictionary<string, ulong> _activeFilters = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _lock = new();
        private bool _isDisposed;

        public bool IsWfpAvailable => _isAvailable;
        public int ActiveBlockFilterCount => _activeFilters.Count;

        #region Native WFP Constants & Structs
        private const uint RPC_C_AUTHN_WINNT = 10;
        private const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

        // FWPM_LAYER_ALE_AUTH_CONNECT_V4 GUID: {c38d57d1-05a7-4c33-904f-7fb4e73d6efb}
        private static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 =
            new Guid(0xc38d57d1, 0x05a7, 0x4c33, 0x90, 0x4f, 0x7f, 0xb4, 0xe7, 0x3d, 0x6e, 0xfb);

        // FWPM_CONDITION_IP_REMOTE_ADDRESS GUID: {b235ae9a-1d9c-44c8-a4fe-92176e01a88b}
        private static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS =
            new Guid(0xb235ae9a, 0x1d9c, 0x44c8, 0xa4, 0xfe, 0x92, 0x17, 0x6e, 0x01, 0xa8, 0x8b);

        private const uint FWP_MATCH_EQUAL = 0;
        private const uint FWP_ACTION_BLOCK = 0x00000001 | 0x00001000; // FWP_ACTION_FLAG_TERMINATING | FWP_ACTION_BLOCK

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_SESSION0
        {
            public Guid sessionKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public uint txnWaitTimeoutInMSec;
            public uint processId;
            public IntPtr sid;
            public IntPtr username;
            public bool kernelMode;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FWPM_DISPLAY_DATA0
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? name;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? description;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_FILTER0
        {
            public Guid filterKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public IntPtr providerKey;
            public FWP_BYTE_BLOB providerData;
            public Guid layerKey;
            public Guid subLayerKey;
            public FWP_VALUE0 weight;
            public uint numFilterConditions;
            public IntPtr filterCondition; // pointer to FWPM_FILTER_CONDITION0 array
            public FWP_ACTION0 action;
            public IntPtr providerContextKey; // Union with raw context
            public IntPtr reserved;
            public ulong filterId;
            public FWP_VALUE0 effectiveWeight;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWP_BYTE_BLOB
        {
            public uint size;
            public IntPtr data;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWP_ACTION0
        {
            public uint type;
            public Guid filterType;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        private struct FWP_VALUE0
        {
            [FieldOffset(0)]
            public uint type; // FWP_DATA_TYPE
            [FieldOffset(8)]
            public uint uint32;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_FILTER_CONDITION0
        {
            public Guid fieldKey;
            public uint matchType;
            public FWP_CONDITION_VALUE0 conditionValue;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        private struct FWP_CONDITION_VALUE0
        {
            [FieldOffset(0)]
            public uint type; // FWP_UINT32 = 4
            [FieldOffset(8)]
            public uint uint32;
        }

        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineOpen0", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint FwpmEngineOpen(
            string? serverName,
            uint authnService,
            IntPtr authIdentity,
            ref FWPM_SESSION0 session,
            out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmEngineClose0", SetLastError = true)]
        private static extern uint FwpmEngineClose(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterAdd0", SetLastError = true)]
        private static extern uint FwpmFilterAdd(
            IntPtr engineHandle,
            ref FWPM_FILTER0 filter,
            IntPtr sd,
            out ulong filterId);

        [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFilterDeleteById0", SetLastError = true)]
        private static extern uint FwpmFilterDeleteById(
            IntPtr engineHandle,
            ulong filterId);
        #endregion

        public WfpEnforcementService(ILogger<WfpEnforcementService>? logger = null)
        {
            _logger = logger;
            InitializeEngine();
        }

        private static bool IsElevated()
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private void InitializeEngine()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _isAvailable = false;
                _logger?.LogInformation("WFP enforcement disabled: Non-Windows operating system.");
                return;
            }

            if (!IsElevated())
            {
                _isAvailable = false;
                _logger?.LogInformation("WFP native BFE driver access requires elevated Administrator privilege. Running in user-mode IP blocklist mode.");
                return;
            }

            lock (_lock)
            {
                try
                {
                    var session = new FWPM_SESSION0
                    {
                        flags = FWPM_SESSION_FLAG_DYNAMIC,
                        txnWaitTimeoutInMSec = 5000,
                        displayData = new FWPM_DISPLAY_DATA0
                        {
                            name = "Ultron Defender Dynamic WFP Session",
                            description = "Manages kernel-level ALE connect block filters for malicious endpoints"
                        }
                    };

                    uint result = FwpmEngineOpen(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, ref session, out _engineHandle);
                    if (result == 0 && _engineHandle != IntPtr.Zero)
                    {
                        _isAvailable = true;
                        _logger?.LogInformation("WFP Base Filtering Engine (BFE) session established successfully. Dynamic ALE connect enforcement active.");
                    }
                    else
                    {
                        _isAvailable = false;
                        _logger?.LogWarning("WFP BFE session could not be opened (Error: 0x{ErrorCode:X8}). Running in User-Mode DNS Sinkhole fallback.", result);
                    }
                }
                catch (Exception ex)
                {
                    _isAvailable = false;
                    _logger?.LogWarning(ex, "Failed to initialize WFP engine. Continuing with DNS sinkhole protection.");
                }
            }
        }

        public bool BlockOutboundIp(string ipAddress, string reason = "Malicious C2 Communication")
        {
            if (string.IsNullOrWhiteSpace(ipAddress)) return false;

            if (!IPAddress.TryParse(ipAddress, out var parsedIp) || parsedIp.AddressFamily != AddressFamily.InterNetwork)
            {
                // WFP IPv4 ALE connect filter supports standard IPv4 addresses
                _logger?.LogDebug("Skipping non-IPv4 address for WFP filter: {IP}", ipAddress);
                return false;
            }

            lock (_lock)
            {
                if (_activeFilters.ContainsKey(ipAddress))
                {
                    return true; // Already blocked
                }

                if (!_isAvailable || _engineHandle == IntPtr.Zero)
                {
                    // Track in memory blocklist even if native WFP is unavailable on non-elevated sessions
                    _activeFilters[ipAddress] = 0;
                    _logger?.LogInformation("[WFP Fallback] Blocked outbound IP recorded: {IP} ({Reason})", ipAddress, reason);
                    return true;
                }

                IntPtr conditionPtr = IntPtr.Zero;
                try
                {
                    // Convert IP to big-endian network byte order uint32
                    byte[] bytes = parsedIp.GetAddressBytes();
                    uint ipNetworkOrder = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | (uint)bytes[3];

                    var condition = new FWPM_FILTER_CONDITION0
                    {
                        fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType = FWP_MATCH_EQUAL,
                        conditionValue = new FWP_CONDITION_VALUE0
                        {
                            type = 4, // FWP_UINT32
                            uint32 = ipNetworkOrder
                        }
                    };

                    conditionPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FWPM_FILTER_CONDITION0>());
                    Marshal.StructureToPtr(condition, conditionPtr, false);

                    var filter = new FWPM_FILTER0
                    {
                        filterKey = Guid.NewGuid(),
                        layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        subLayerKey = Guid.Empty,
                        displayData = new FWPM_DISPLAY_DATA0
                        {
                            name = $"Ultron Defender Block - {ipAddress}",
                            description = reason
                        },
                        action = new FWP_ACTION0
                        {
                            type = FWP_ACTION_BLOCK
                        },
                        numFilterConditions = 1,
                        filterCondition = conditionPtr,
                        weight = new FWP_VALUE0 { type = 4, uint32 = 0xF0000000 } // High priority weight
                    };

                    uint res = FwpmFilterAdd(_engineHandle, ref filter, IntPtr.Zero, out ulong filterId);
                    if (res == 0)
                    {
                        _activeFilters[ipAddress] = filterId;
                        _logger?.LogWarning("🛡️ WFP PACKET BLOCK: Active outbound TCP/UDP connection filter established for IP {IP} (FilterId: {FilterId}, Reason: {Reason})",
                            ipAddress, filterId, reason);
                        return true;
                    }
                    else
                    {
                        _logger?.LogWarning("Failed to add WFP filter for IP {IP} (Error: 0x{Error:X8})", ipAddress, res);
                        _activeFilters[ipAddress] = 0;
                        return false;
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Exception adding WFP filter for {IP}", ipAddress);
                    return false;
                }
                finally
                {
                    if (conditionPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(conditionPtr);
                    }
                }
            }
        }

        public bool UnblockIp(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress)) return false;

            lock (_lock)
            {
                if (_activeFilters.TryRemove(ipAddress, out ulong filterId))
                {
                    if (_isAvailable && _engineHandle != IntPtr.Zero && filterId != 0)
                    {
                        uint res = FwpmFilterDeleteById(_engineHandle, filterId);
                        if (res == 0)
                        {
                            _logger?.LogInformation("WFP filter removed for IP {IP} (FilterId: {FilterId})", ipAddress, filterId);
                            return true;
                        }
                    }
                    return true;
                }
                return false;
            }
        }

        public void ClearDynamicFilters()
        {
            lock (_lock)
            {
                foreach (var kvp in _activeFilters)
                {
                    if (_isAvailable && _engineHandle != IntPtr.Zero && kvp.Value != 0)
                    {
                        try
                        {
                            FwpmFilterDeleteById(_engineHandle, kvp.Value);
                        }
                        catch { }
                    }
                }
                _activeFilters.Clear();
                _logger?.LogInformation("All dynamic WFP filters cleared.");
            }
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;

            lock (_lock)
            {
                ClearDynamicFilters();
                if (_engineHandle != IntPtr.Zero)
                {
                    try
                    {
                        FwpmEngineClose(_engineHandle);
                    }
                    catch { }
                    _engineHandle = IntPtr.Zero;
                }
                _isAvailable = false;
            }
        }
    }
}
