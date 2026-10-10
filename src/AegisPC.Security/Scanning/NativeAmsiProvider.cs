using System;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning;

/// <summary>Supplies the native AMSI boundary; an injected provider permits decision tests without native calls or registration.</summary>
public interface IAmsiNativeProvider : IDisposable
{
    /// <summary>Reports whether a native context is initialized; availability alone is not a completed scan.</summary>
    bool IsAvailable { get; }
    /// <summary>Provides the initialization HRESULT if obtained, including a failure code; unavailable libraries have no code.</summary>
    int? InitializationHResult { get; }
    /// <summary>Returns the native HRESULT and AMSI_RESULT for the complete null-terminated string.</summary>
    NativeAmsiScanResponse ScanString(string content, string contentName);
    /// <summary>Returns the native HRESULT and AMSI_RESULT for all supplied bytes.</summary>
    NativeAmsiScanResponse ScanBuffer(byte[] content, string contentName);
}

/// <summary>Preserves native output without deciding whether it represents successful inspection.</summary>
public readonly struct NativeAmsiScanResponse
{
    /// <summary>Captures native output; RawResult is meaningful only when the HRESULT indicates scan success.</summary>
    public NativeAmsiScanResponse(int hResult, int rawResult) { HResult = hResult; RawResult = rawResult; }
    /// <summary>Contains the native request HRESULT; AMSI scanning requires S_OK.</summary>
    public int HResult { get; }
    /// <summary>Contains the native AMSI_RESULT, whose malware threshold and admin-block range are distinct.</summary>
    public int RawResult { get; }
}

internal sealed class NativeAmsiProvider : IAmsiNativeProvider
{
    private readonly object _gate = new();
    private readonly ILogger? _logger;
    private IntPtr _context;
    public int? InitializationHResult { get; private set; }
    public bool IsAvailable { get { lock (_gate) return _context != IntPtr.Zero; } }

    internal NativeAmsiProvider(ILogger? logger)
    {
        _logger = logger;
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            InitializationHResult = AmsiInitialize("UltronDefender_AMSI_Engine", out _context);
            if (InitializationHResult != 0 || _context == IntPtr.Zero)
            {
                _logger?.LogWarning("AMSI initialization was unavailable; HRESULT={HResult}.", InitializationHResult);
                Dispose();
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        { _logger?.LogWarning(ex, "The native AMSI library was unavailable."); _context = IntPtr.Zero; }
    }

    public NativeAmsiScanResponse ScanString(string content, string contentName)
    {
        lock (_gate)
        {
            if (_context == IntPtr.Zero) throw new InvalidOperationException("Native AMSI context is unavailable.");
            // The session argument is optional; unrelated requests are not retained in one indefinite correlation session.
            int hr = AmsiScanString(_context, content, contentName, IntPtr.Zero, out int raw);
            return new NativeAmsiScanResponse(hr, raw);
        }
    }

    public NativeAmsiScanResponse ScanBuffer(byte[] content, string contentName)
    {
        lock (_gate)
        {
            if (_context == IntPtr.Zero) throw new InvalidOperationException("Native AMSI context is unavailable.");
            int hr = AmsiScanBuffer(_context, content, checked((uint)content.Length), contentName, IntPtr.Zero, out int raw);
            return new NativeAmsiScanResponse(hr, raw);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_context == IntPtr.Zero) return;
            var context = _context;
            _context = IntPtr.Zero;
            try { AmsiUninitialize(context); }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
            { _logger?.LogWarning(ex, "Native AMSI cleanup failed."); }
        }
    }

    [DllImport("amsi.dll", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
    private static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)] string appName, out IntPtr context);
    [DllImport("amsi.dll", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
    private static extern int AmsiScanString(IntPtr context, [MarshalAs(UnmanagedType.LPWStr)] string content,
        [MarshalAs(UnmanagedType.LPWStr)] string contentName, IntPtr session, out int result);
    [DllImport("amsi.dll", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
    private static extern int AmsiScanBuffer(IntPtr context, byte[] content, uint length,
        [MarshalAs(UnmanagedType.LPWStr)] string contentName, IntPtr session, out int result);
    [DllImport("amsi.dll", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
    private static extern void AmsiUninitialize(IntPtr context);
}
