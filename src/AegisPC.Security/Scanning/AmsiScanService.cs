using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Microsoft Antimalware Scan Interface (AMSI) Win32 API Sarmalayıcısı.
    /// Bellek içi PowerShell, VBScript, Macro ve dinamik betikleri amsi.dll üzerinden analiz eder.
    /// </summary>
    public class AmsiScanService : IAmsiScanService
    {
        private readonly ILogger<AmsiScanService>? _logger;
        private IntPtr _amsiContext = IntPtr.Zero;
        private IntPtr _amsiSession = IntPtr.Zero;
        private bool _isInitialized;
        private readonly object _lock = new();

        public bool IsAmsiSupported => _isInitialized && _amsiContext != IntPtr.Zero;

        #region Win32 Native AMSI P/Invoke
        [DllImport("amsi.dll", EntryPoint = "AmsiInitialize", CallingConvention = CallingConvention.StdCall)]
        private static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)] string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll", EntryPoint = "AmsiOpenSession", CallingConvention = CallingConvention.StdCall)]
        private static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr amsiSession);

        [DllImport("amsi.dll", EntryPoint = "AmsiScanString", CallingConvention = CallingConvention.StdCall)]
        private static extern int AmsiScanString(
            IntPtr amsiContext,
            [MarshalAs(UnmanagedType.LPWStr)] string @string,
            [MarshalAs(UnmanagedType.LPWStr)] string contentName,
            IntPtr amsiSession,
            out int result);

        [DllImport("amsi.dll", EntryPoint = "AmsiScanBuffer", CallingConvention = CallingConvention.StdCall)]
        private static extern int AmsiScanBuffer(
            IntPtr amsiContext,
            byte[] buffer,
            uint length,
            [MarshalAs(UnmanagedType.LPWStr)] string contentName,
            IntPtr amsiSession,
            out int result);

        [DllImport("amsi.dll", EntryPoint = "AmsiCloseSession", CallingConvention = CallingConvention.StdCall)]
        private static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr amsiSession);

        [DllImport("amsi.dll", EntryPoint = "AmsiUninitialize", CallingConvention = CallingConvention.StdCall)]
        private static extern void AmsiUninitialize(IntPtr amsiContext);

        private const int AMSI_RESULT_CLEAN = 0;
        private const int AMSI_RESULT_NOT_DETECTED = 1;
        private const int AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384;
        private const int AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479;
        private const int AMSI_RESULT_DETECTED = 32768;
        #endregion

        public AmsiScanService(ILogger<AmsiScanService>? logger = null)
        {
            _logger = logger;
            InitializeAmsi();
        }

        private void InitializeAmsi()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _logger?.LogWarning("AMSI is only supported on Windows platform.");
                return;
            }

            lock (_lock)
            {
                try
                {
                    int hr = AmsiInitialize("UltronDefender_AMSI_Engine", out _amsiContext);
                    if (hr == 0 && _amsiContext != IntPtr.Zero)
                    {
                        AmsiOpenSession(_amsiContext, out _amsiSession);
                        _isInitialized = true;
                        _logger?.LogInformation("Windows Antimalware Scan Interface (AMSI) successfully initialized.");
                    }
                    else
                    {
                        _logger?.LogWarning("AmsiInitialize returned HRESULT 0x{Hr:X8}", hr);
                    }
                }
                catch (DllNotFoundException)
                {
                    _logger?.LogWarning("amsi.dll not found on this Windows build.");
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to initialize AMSI provider.");
                }
            }
        }

        public async Task<AmsiScanResult> ScanStringAsync(string content, string contentName = "DynamicScript")
        {
            if (string.IsNullOrEmpty(content))
            {
                return new AmsiScanResult { Result = AmsiDetectionResult.Clean, ContentName = contentName };
            }

            var sw = Stopwatch.StartNew();

            // 1. If AMSI is active, perform native scan
            if (IsAmsiSupported)
            {
                try
                {
                    int rawResult = 0;
                    int hr;

                    lock (_lock)
                    {
                        hr = AmsiScanString(_amsiContext, content, contentName, _amsiSession, out rawResult);
                    }

                    if (hr == 0 && rawResult >= AMSI_RESULT_DETECTED)
                    {
                        sw.Stop();
                        return new AmsiScanResult
                        {
                            IsMalicious = true,
                            Result = AmsiDetectionResult.Malicious,
                            RawResultCode = rawResult,
                            ContentName = contentName,
                            Details = $"AMSI Tehdit Tespiti (Kod: {rawResult})",
                            ScanDuration = sw.Elapsed
                        };
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "AMSI ScanString call failed, falling back to heuristic script scanner.");
                }
            }

            // 2. Heuristic Cross-Check & Fallback
            return await Task.Run(() => EvaluateScriptHeuristics(content, contentName, sw.Elapsed));
        }

        public async Task<AmsiScanResult> ScanBufferAsync(byte[] buffer, string contentName = "MemoryBuffer")
        {
            if (buffer == null || buffer.Length == 0)
            {
                return new AmsiScanResult { Result = AmsiDetectionResult.Clean, ContentName = contentName };
            }

            var sw = Stopwatch.StartNew();

            if (IsAmsiSupported)
            {
                try
                {
                    int rawResult = 0;
                    int hr;

                    lock (_lock)
                    {
                        hr = AmsiScanBuffer(_amsiContext, buffer, (uint)buffer.Length, contentName, _amsiSession, out rawResult);
                    }

                    if (hr == 0 && rawResult >= AMSI_RESULT_DETECTED)
                    {
                        sw.Stop();
                        return new AmsiScanResult
                        {
                            IsMalicious = true,
                            Result = AmsiDetectionResult.Malicious,
                            RawResultCode = rawResult,
                            ContentName = contentName,
                            Details = $"AMSI Bellek İhlali (Kod: {rawResult})",
                            ScanDuration = sw.Elapsed
                        };
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "AMSI ScanBuffer call failed, falling back to buffer heuristic scanner.");
                }
            }

            var text = Encoding.UTF8.GetString(buffer);
            return await Task.Run(() => EvaluateScriptHeuristics(text, contentName, sw.Elapsed));
        }

        private AmsiScanResult EvaluateScriptHeuristics(string content, string contentName, TimeSpan duration)
        {
            // Detect EICAR standard test pattern
            if (content.Contains("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"))
            {
                return new AmsiScanResult
                {
                    IsMalicious = true,
                    Result = AmsiDetectionResult.Malicious,
                    RawResultCode = AMSI_RESULT_DETECTED,
                    ContentName = contentName,
                    Details = "EICAR Test İmzası Tespit Edildi (Heuristic Fallback)",
                    ScanDuration = duration
                };
            }

            // Detect AMSI Bypass attempts & Obfuscated PowerShell Droppers
            var lower = content.ToLowerInvariant();
            if (lower.Contains("amsiinitfailed") || 
                lower.Contains("amsiutils") && lower.Contains("nonpublic") ||
                lower.Contains("[ref].assembly.gettype('system.management.automation.amsiutils')") ||
                lower.Contains("downloadstring") && lower.Contains("iex") && lower.Contains("bypass"))
            {
                return new AmsiScanResult
                {
                    IsMalicious = true,
                    Result = AmsiDetectionResult.Malicious,
                    RawResultCode = AMSI_RESULT_DETECTED,
                    ContentName = contentName,
                    Details = "Şüpheli AMSI Bypass veya Obfuscated PowerShell Kodu Tespit Edildi",
                    ScanDuration = duration
                };
            }

            return new AmsiScanResult
            {
                IsMalicious = false,
                Result = AmsiDetectionResult.Clean,
                RawResultCode = 0,
                ContentName = contentName,
                Details = "Temiz Betik",
                ScanDuration = duration
            };
        }

        public void Dispose()
        {
            lock (_lock)
            {
                try
                {
                    if (_amsiSession != IntPtr.Zero && _amsiContext != IntPtr.Zero)
                    {
                        AmsiCloseSession(_amsiContext, _amsiSession);
                        _amsiSession = IntPtr.Zero;
                    }

                    if (_amsiContext != IntPtr.Zero)
                    {
                        AmsiUninitialize(_amsiContext);
                        _amsiContext = IntPtr.Zero;
                    }
                    _isInitialized = false;
                }
                catch { }
            }
        }
    }
}
