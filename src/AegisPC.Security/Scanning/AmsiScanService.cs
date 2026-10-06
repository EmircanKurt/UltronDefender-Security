using System;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning;

/// <summary>
/// Queries an installed native AMSI provider and separately records bounded local review hints.
/// Native errors or unsupported coverage never become clean or fabricated native-malware verdicts.
/// </summary>
public sealed class AmsiScanService : IAmsiScanService, IAmsiObservationProvider
{
    private const int MaximumHeuristicInput = 128 * 1024;
    private const int AdminBlockStart = 16384;
    private const int AdminBlockEnd = 20479;
    private const int MalwareThreshold = 32768;
    private readonly IAmsiNativeProvider _nativeProvider;
    private readonly ILogger<AmsiScanService>? _logger;
    private bool _disposed;
    private readonly object _observationGate = new();
    private DateTime? _lastNativeScanUtc;
    private bool _lastNativeRequestCompleted;

    /// <summary>Returns the last completed native-provider observation, not a heuristic or canonical fallback timestamp.</summary>
    public DateTime? LastNativeScanUtc { get { lock (_observationGate) return _lastNativeScanUtc; } }
    /// <summary>Reports the last native request's successful completion independently of initialization support.</summary>
    public bool LastNativeRequestCompleted { get { lock (_observationGate) return _lastNativeRequestCompleted; } }

    /// <summary>Reports initialized native-provider availability, not successful inspection or independent Ultron script interception.</summary>
    public bool IsAmsiSupported => !_disposed && _nativeProvider.IsAvailable;

    /// <summary>Owns the supplied native provider or creates the Windows adapter; injection permits inert decision tests.</summary>
    public AmsiScanService(ILogger<AmsiScanService>? logger = null, IAmsiNativeProvider? nativeProvider = null)
    {
        _logger = logger;
        _nativeProvider = nativeProvider ?? new NativeAmsiProvider(logger);
    }

    /// <summary>Inspects the supplied string without executing it; native status and heuristic hints remain separate.</summary>
    public Task<AmsiScanResult> ScanStringAsync(string content, string contentName = "DynamicScript")
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (string.IsNullOrEmpty(content)) return Task.FromResult(EmptyResult(contentName));
        return Task.Run(() =>
        {
            var watch = Stopwatch.StartNew();
            string inspectedText = content.Length <= MaximumHeuristicInput ? content : content[..MaximumHeuristicInput];
            var indicators = InspectHeuristicReferences(inspectedText);
            bool canonical = content.Length <= 128 &&
                MalwareSignatureDatabase.CheckCanonicalTestContent(Encoding.UTF8.GetBytes(content)).IsMatched;
            // LPCWSTR would stop at an embedded NUL. Preserve the entire input with the length-aware buffer API.
            return EvaluateNative(() => content.Contains('\0')
                ? _nativeProvider.ScanBuffer(Encoding.Unicode.GetBytes(content), contentName)
                : _nativeProvider.ScanString(content, contentName), contentName, indicators, canonical, watch);
        });
    }

    /// <summary>Inspects all supplied bytes natively; local fallback reviews at most a bounded UTF-8 prefix and remains incomplete.</summary>
    public Task<AmsiScanResult> ScanBufferAsync(byte[] buffer, string contentName = "MemoryBuffer")
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer == null || buffer.Length == 0) return Task.FromResult(EmptyResult(contentName));
        return Task.Run(() =>
        {
            var watch = Stopwatch.StartNew();
            var indicators = InspectHeuristicReferences(Encoding.UTF8.GetString(buffer, 0, Math.Min(buffer.Length, MaximumHeuristicInput)));
            bool canonical = buffer.Length <= 128 && MalwareSignatureDatabase.CheckCanonicalTestContent(buffer).IsMatched;
            return EvaluateNative(() => _nativeProvider.ScanBuffer(buffer, contentName), contentName, indicators, canonical, watch);
        });
    }

    private AmsiScanResult EvaluateNative(Func<NativeAmsiScanResponse> request, string contentName,
        AmsiHeuristicIndicators indicators, bool canonical, Stopwatch watch)
    {
        int? hResult = _nativeProvider.InitializationHResult;
        var status = AmsiNativeScanStatus.Unavailable;
        try
        {
            if (_nativeProvider.IsAvailable)
            {
                hResult = null; // Initialization success is not a scan HRESULT when the call throws.
                var response = request();
                hResult = response.HResult;
                status = AmsiNativeScanStatus.Failed;
                if (response.HResult == 0 && response.RawResult >= 0)
                {
                    var result = response.RawResult >= MalwareThreshold ? AmsiDetectionResult.Malicious :
                        response.RawResult is >= AdminBlockStart and <= AdminBlockEnd ? AmsiDetectionResult.BlockedByAdmin :
                        response.RawResult == 0 ? AmsiDetectionResult.Clean : AmsiDetectionResult.NotDetected;
                    bool localTestMatch = canonical && result != AmsiDetectionResult.Malicious;
                    if (localTestMatch) result = AmsiDetectionResult.Malicious;
                    RecordNativeObservation(!localTestMatch);
                    watch.Stop();
                    return new AmsiScanResult
                    {
                        IsMalicious = result == AmsiDetectionResult.Malicious,
                        Result = result, RawResultCode = response.RawResult,
                        Source = localTestMatch ? AmsiVerdictSource.CanonicalTestSignature : AmsiVerdictSource.NativeProvider,
                        NativeStatus = AmsiNativeScanStatus.Completed, NativeHResult = hResult, IsComplete = true,
                        HeuristicIndicators = indicators, ContentName = contentName, ScanDuration = watch.Elapsed,
                        Details = localTestMatch
                            ? $"Tam içerik standart antivirüs test dosyasıyla eşleşti; yerel AMSI sonucu ayrı kaydedildi ({response.RawResult})."
                            : result == AmsiDetectionResult.BlockedByAdmin
                            ? "İçerik yerel yönetici AMSI politikası tarafından engellendi; bu sonuç zararlı sınıflandırması değildir."
                            : $"Yerel AMSI sağlayıcısı incelemeyi tamamladı (sonuç: {response.RawResult})."
                    };
                }
                _logger?.LogWarning("Native AMSI did not return a valid scan result; HRESULT={HResult}, result={Result}.", hResult, response.RawResult);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
        {
            hResult = null;
            status = AmsiNativeScanStatus.Failed;
            _logger?.LogWarning(ex, "Native AMSI inspection failed; local hints do not establish a provider verdict.");
        }

        watch.Stop();
        RecordNativeObservation(false);
        return new AmsiScanResult
        {
            IsMalicious = canonical,
            Result = canonical ? AmsiDetectionResult.Malicious : indicators != AmsiHeuristicIndicators.None
                ? AmsiDetectionResult.Suspicious : AmsiDetectionResult.Unknown,
            Source = canonical ? AmsiVerdictSource.CanonicalTestSignature : AmsiVerdictSource.HeuristicFallback,
            NativeStatus = status, NativeHResult = hResult, IsComplete = false, RawResultCode = 0,
            HeuristicIndicators = indicators, ContentName = contentName, ScanDuration = watch.Elapsed,
            Details = canonical ? "Tam içerik standart antivirüs test dosyasıyla eşleşti; yerel AMSI incelemesi tamamlanmadı."
                : indicators != AmsiHeuristicIndicators.None
                    ? "Sezgisel inceleme sinyali bulundu; yerel AMSI kapsamı eksik ve zararlı olduğu doğrulanmadı."
                    : "Yerel AMSI incelemesi tamamlanmadı; incelenen metinde ipucu bulunmaması temiz sonucu değildir."
        };
    }

    private void RecordNativeObservation(bool completed)
    {
        lock (_observationGate)
        {
            _lastNativeRequestCompleted = completed;
            if (completed) _lastNativeScanUtc = DateTime.UtcNow;
        }
    }

    private static AmsiHeuristicIndicators InspectHeuristicReferences(string content)
    {
        string lower = content.ToLowerInvariant();
        var hints = AmsiHeuristicIndicators.None;
        if (lower.Contains("amsiinitfailed", StringComparison.Ordinal) ||
            (lower.Contains("amsiutils", StringComparison.Ordinal) && lower.Contains("nonpublic", StringComparison.Ordinal)))
            hints |= AmsiHeuristicIndicators.DefenseEvasionReference;
        if (lower.Contains("downloadstring", StringComparison.Ordinal) && lower.Contains("iex", StringComparison.Ordinal))
            hints |= AmsiHeuristicIndicators.DownloadExecutionReference;
        if ((lower.Contains("vssadmin", StringComparison.Ordinal) && lower.Contains("delete", StringComparison.Ordinal) && lower.Contains("shadows", StringComparison.Ordinal)) ||
            (lower.Contains("bcdedit", StringComparison.Ordinal) && lower.Contains("recoveryenabled", StringComparison.Ordinal) && lower.Contains("no", StringComparison.Ordinal)))
            hints |= AmsiHeuristicIndicators.RecoveryTamperingReference;
        return hints;
    }

    private static AmsiScanResult EmptyResult(string contentName) => new()
    {
        Result = AmsiDetectionResult.Clean, Source = AmsiVerdictSource.EmptyInput,
        NativeStatus = AmsiNativeScanStatus.NotAttempted, IsComplete = true, ContentName = contentName,
        Details = "İncelenecek içerik yok."
    };

    /// <summary>Releases the owned provider; subsequent requests throw instead of reporting clean coverage.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _nativeProvider.Dispose();
    }
}
