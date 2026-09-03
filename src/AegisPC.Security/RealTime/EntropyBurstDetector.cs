using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Fidye virüsü şifreleme patlamalarını (burst) ve dosya entropi delta anomalilerini saptayan bileşen arayüzü.
    /// </summary>
    public interface IEntropyBurstDetector : IDisposable
    {
        /// <summary>
        /// Belirtilen dosya uzantısının bilinen bir fidye şifreleme uzantısı olup olmadığını kontrol eder.
        /// </summary>
        bool IsKnownRansomwareExtension(string ext);

        /// <summary>
        /// Değiştirilen dosyanın Shannon entropisindeki ani artışı (delta) denetler.
        /// </summary>
        Task CheckEntropyDeltaAsync(string fullPath, Func<string, string, int, Task> onThreatDetected);

        /// <summary>
        /// Kısa zaman aralığında (2.5 saniye) kitle modifikasyon ve şifreleme hızını denetler.
        /// </summary>
        void CheckRansomwareBurst(string path, string operation, Func<string, string, int, Task> onThreatDetected);

        /// <summary>
        /// Tüm önbellekleri ve sayaçları temizler.
        /// </summary>
        void Clear();
    }

    /// <summary>
    /// Shannon entropi sıçramalarını ve kitle dosya modifikasyon anomalilerini analiz eden dedektör.
    /// </summary>
    public class EntropyBurstDetector : IEntropyBurstDetector
    {
        private static readonly string[] KnownRansomwareExtensions = new[]
        {
            ".locked", ".crypto", ".enc", ".encrypted", ".dark", ".ransom", ".crypt",
            ".crinf", ".r5a", ".locky", ".cerber", ".wannacry", ".wncry", ".micro",
            ".crypted", ".vault", ".stop", ".djvu", ".phobos", ".dharma", ".blackmatter", ".lockbit"
        };

        private readonly ConcurrentDictionary<string, double> _fileEntropyCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentQueue<DateTime> _globalRapidChanges = new();
        private readonly SemaphoreSlim _entropyThrottle = new(4, 4);
        private Timer? _entropyCacheCleanupTimer;
        private const int MaxEntropyCacheEntries = 5000;

        public EntropyBurstDetector()
        {
            _entropyCacheCleanupTimer = new Timer(_ =>
            {
                if (_fileEntropyCache.Count > MaxEntropyCacheEntries)
                {
                    int toRemove = _fileEntropyCache.Count / 2;
                    int removed = 0;
                    foreach (var key in _fileEntropyCache.Keys)
                    {
                        if (removed >= toRemove) break;
                        _fileEntropyCache.TryRemove(key, out double _);
                        removed++;
                    }
                }
            }, null, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15));
        }

        public bool IsKnownRansomwareExtension(string ext)
        {
            if (string.IsNullOrWhiteSpace(ext)) return false;
            return KnownRansomwareExtensions.Contains(ext.ToLowerInvariant());
        }

        public async Task CheckEntropyDeltaAsync(string fullPath, Func<string, string, int, Task> onThreatDetected)
        {
            if (!await _entropyThrottle.WaitAsync(100)) return;
            try
            {
                if (File.Exists(fullPath))
                {
                    var ext = Path.GetExtension(fullPath).ToLowerInvariant();
                    if (ext is ".docx" or ".xlsx" or ".pdf" or ".txt" or ".jpg")
                    {
                        var currentEntropy = await EntropyCalculator.CalculateEntropyAsync(fullPath);
                        if (_fileEntropyCache.TryGetValue(fullPath, out var previousEntropy))
                        {
                            if (currentEntropy - previousEntropy > 2.8 && currentEntropy > 7.5)
                            {
                                await onThreatDetected(
                                    fullPath,
                                    $"⚠️ Anormal Yüksek Entropi Sıçraması ({previousEntropy:F2} -> {currentEntropy:F2}). Şifreleme saldırısı şüphesi!",
                                    85);
                            }
                        }
                        _fileEntropyCache[fullPath] = currentEntropy;
                    }
                }
            }
            catch { }
            finally
            {
                _entropyThrottle.Release();
            }
        }

        public void CheckRansomwareBurst(string path, string operation, Func<string, string, int, Task> onThreatDetected)
        {
            var now = DateTime.UtcNow;
            _globalRapidChanges.Enqueue(now);

            while (_globalRapidChanges.TryPeek(out var oldest) && (now - oldest).TotalSeconds > 2.5)
            {
                _globalRapidChanges.TryDequeue(out _);
            }

            if (_globalRapidChanges.Count >= 20)
            {
                _globalRapidChanges.Clear();
                _ = onThreatDetected(
                    path,
                    $"🚨 Kitle Dosya Modifikasyon Anomalisi (2.5 saniyede 20+ dosya işlem gördü)!",
                    90);
            }
        }

        public void Clear()
        {
            _fileEntropyCache.Clear();
            while (_globalRapidChanges.TryDequeue(out _)) { }
        }

        public void Dispose()
        {
            _entropyCacheCleanupTimer?.Dispose();
            _entropyCacheCleanupTimer = null;
            Clear();
            _entropyThrottle.Dispose();
        }
    }
}
