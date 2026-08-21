using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.App.Services
{
    /// <summary>
    /// Akıllı Bildirim Birleştirme (Notification Aggregator & Debouncer) özellikli
    /// Windows Toast ve Sistem Tepsisi Bildirim Servisi.
    /// Arka arkaya gelen çoklu tehdit bildirimlerini tek bir özet bildirimde birleştirir.
    /// </summary>
    public class WindowsToastNotificationService : IWindowsToastNotificationService, IDisposable
    {
        private readonly ILogger<WindowsToastNotificationService>? _logger;
        private readonly ISystemTrayService? _trayService;

        private readonly ConcurrentQueue<ThreatToastItem> _threatQueue = new();
        private readonly ConcurrentDictionary<string, DateTime> _recentNotificationCache = new();
        private readonly System.Threading.Timer _aggregationTimer;
        private int _isFlushing;

        public TimeSpan AggregationWindow { get; set; } = TimeSpan.FromMilliseconds(2500);

        public WindowsToastNotificationService(
            ISystemTrayService? trayService = null,
            ILogger<WindowsToastNotificationService>? logger = null)
        {
            _trayService = trayService;
            _logger = logger;
            _aggregationTimer = new System.Threading.Timer(OnTimerTick, null, Timeout.Infinite, Timeout.Infinite);
        }

        public void ShowToast(string title, string message, string type = "Info")
        {
            try
            {
                // Cooldown & Deduplication check: suppress identical notifications within 10 seconds
                string cacheKey = $"{title}_{message}";
                var now = DateTime.UtcNow;
                if (_recentNotificationCache.TryGetValue(cacheKey, out var lastTime) && (now - lastTime).TotalSeconds < 10)
                {
                    return;
                }
                _recentNotificationCache[cacheKey] = now;

                bool isThreat = type.Equals("Warning", StringComparison.OrdinalIgnoreCase) ||
                                type.Equals("Error", StringComparison.OrdinalIgnoreCase) ||
                                type.Equals("Danger", StringComparison.OrdinalIgnoreCase) ||
                                title.Contains("Tehdit", StringComparison.OrdinalIgnoreCase) ||
                                title.Contains("Zararlı", StringComparison.OrdinalIgnoreCase) ||
                                title.Contains("Fidye", StringComparison.OrdinalIgnoreCase);

                if (isThreat)
                {
                    _threatQueue.Enqueue(new ThreatToastItem
                    {
                        Title = title,
                        Message = message,
                        Type = type,
                        Timestamp = DateTime.UtcNow
                    });

                    // Start or reset aggregation timer (2.5s debounce window)
                    _aggregationTimer.Change((int)AggregationWindow.TotalMilliseconds, Timeout.Infinite);
                }
                else
                {
                    // Non-threat info/success notification: emit directly
                    EmitNativeToast(title, message, type);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error enqueueing notification");
            }
        }

        private void OnTimerTick(object? state)
        {
            FlushThreats();
        }

        private void FlushThreats()
        {
            if (Interlocked.Exchange(ref _isFlushing, 1) == 1) return;

            try
            {
                var items = new List<ThreatToastItem>();
                while (_threatQueue.TryDequeue(out var item))
                {
                    items.Add(item);
                }

                if (items.Count == 0) return;

                if (items.Count == 1)
                {
                    var single = items[0];
                    string formattedTitle = FormatAppHeader(single.Title);
                    EmitNativeToast(formattedTitle, single.Message, single.Type);
                }
                else
                {
                    // Multiple threats detected in batch: aggregate into a single clean summary notification per user directive
                    int count = items.Count;
                    string summaryTitle = $"Ultron Defender (Antivirüs Programı) - 🛡️ {count} Tehdit Engellendi ve Karantinaya Alındı";

                    var sampleNames = items
                        .Select(i => 
                        {
                            var t = i.Title.Replace("🚨", "").Replace("🛡️", "").Replace("⚠️", "").Trim();
                            if (t.StartsWith("Ultron Defender", StringComparison.OrdinalIgnoreCase))
                            {
                                int idx = t.IndexOf(':');
                                if (idx > 0 && idx < t.Length - 1) t = t[(idx + 1)..].Trim();
                            }
                            return t;
                        })
                        .Where(s => !string.IsNullOrWhiteSpace(s))
                        .Distinct()
                        .Take(3)
                        .ToList();

                    string sampleList = sampleNames.Count > 0 ? string.Join(", ", sampleNames) : "Tespit edilen dosyalar";
                    string summaryMessage = $"{count} adet zararlı tehdit tespit edildi ve sisteminizden temizlenerek AES-256 Karantina Kasasına kilitlendi.\n({sampleList}{(items.Count > 3 ? "..." : "")})\nDetaylar için Güvenlik Merkezini açın.";

                    EmitNativeToast(summaryTitle, summaryMessage, "Danger");
                }
            }
            finally
            {
                Interlocked.Exchange(ref _isFlushing, 0);
            }
        }

        private static string FormatAppHeader(string title)
        {
            if (string.IsNullOrWhiteSpace(title)) return "Ultron Defender Total Security (Antivirüs Programı)";
            if (title.Contains("Ultron Defender", StringComparison.OrdinalIgnoreCase) && title.Contains("Antivirüs", StringComparison.OrdinalIgnoreCase))
                return title;

            if (title.Contains("Ultron Defender", StringComparison.OrdinalIgnoreCase))
                return title.Replace("Ultron Defender", "Ultron Defender (Antivirüs Programı)");

            return $"Ultron Defender (Antivirüs Programı) - {title}";
        }

        private void EmitNativeToast(string title, string message, string type)
        {
            try
            {
                _logger?.LogInformation("Windows Toast [{Type}]: {Title} - {Message}", type, title, message);

                var icon = type.ToLowerInvariant() switch
                {
                    "error" or "danger" => ToolTipIcon.Error,
                    "warning" => ToolTipIcon.Warning,
                    _ => ToolTipIcon.Info
                };

                string fullTitle = FormatAppHeader(title);

                // Modern Slide-in Floating Toast (Bottom-Right Screen Corner) - Clean, ESET-Style, Silent
                Views.ToastNotificationWindow.ShowToast(fullTitle, message, type);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error firing native notification");
            }
        }

        public void Dispose()
        {
            _aggregationTimer.Dispose();
            FlushThreats();
        }

        private record ThreatToastItem
        {
            public string Title { get; init; } = string.Empty;
            public string Message { get; init; } = string.Empty;
            public string Type { get; init; } = "Info";
            public DateTime Timestamp { get; init; }
        }
    }
}
