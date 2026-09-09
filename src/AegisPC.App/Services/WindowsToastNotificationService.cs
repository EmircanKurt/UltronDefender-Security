using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
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
        private readonly ISettingsService? _settingsService;

        private readonly ConcurrentQueue<ThreatToastItem> _threatQueue = new();
        private readonly ConcurrentDictionary<string, DateTime> _recentNotificationCache = new();
        private readonly System.Threading.Timer _aggregationTimer;
        private int _isFlushing;

        public TimeSpan AggregationWindow { get; set; } = TimeSpan.FromMilliseconds(2500);

        public WindowsToastNotificationService(
            ISystemTrayService? trayService = null,
            ISettingsService? settingsService = null,
            ILogger<WindowsToastNotificationService>? logger = null)
        {
            _trayService = trayService;
            _settingsService = settingsService;
            _logger = logger;
            _aggregationTimer = new System.Threading.Timer(OnTimerTick, null, Timeout.Infinite, Timeout.Infinite);
        }

        public void ShowToast(string title, string message, string type = "Info")
        {
            try
            {
                // 1. Settings check: Suppress notifications if user disabled them in Settings
                var settings = _settingsService ?? (App.ServiceProvider?.GetService(typeof(ISettingsService)) as ISettingsService);
                if (settings != null)
                {
                    bool notificationsEnabled = settings.GetSetting("NotificationsEnabled", true);
                    if (!notificationsEnabled)
                    {
                        return;
                    }
                }

                // 2. Suppress routine background maintenance toasts (e.g. 20-min routine scan clean, daily scan startup announcements)
                if (title.Contains("Rutin Tarama", StringComparison.OrdinalIgnoreCase) ||
                    title.Contains("Günlük Tam Tarama Başlatılıyor", StringComparison.OrdinalIgnoreCase) ||
                    message.Contains("20 dakikalık", StringComparison.OrdinalIgnoreCase) ||
                    message.Contains("planlanmış tam tarama henüz yapılmadığından", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                // 3. Smart Deduplication & Cooldown: tehdit bildirimleri 30 dakika, diğerleri 3 dakika
                bool isThreatLike = type.Equals("Warning", StringComparison.OrdinalIgnoreCase) ||
                                    type.Equals("Error", StringComparison.OrdinalIgnoreCase) ||
                                    type.Equals("Danger", StringComparison.OrdinalIgnoreCase) ||
                                    title.Contains("Tehdit", StringComparison.OrdinalIgnoreCase) ||
                                    title.Contains("Zararlı", StringComparison.OrdinalIgnoreCase) ||
                                    title.Contains("Fidye", StringComparison.OrdinalIgnoreCase);

                string cleanTitle = Regex.Replace(title, @"[\u2600-\u27BF]|[\uD83C-\uDBFF\uDC00-\uDFFF]|[\d]+(\s*(adet|riskli|şüpheli|yeni|tane))?", "", RegexOptions.IgnoreCase).Trim();
                string cleanMsg = Regex.Replace(message, @"[\d]+(\s*(adet|riskli|şüpheli|yeni|tane))?", "", RegexOptions.IgnoreCase).Trim();
                string cacheKey = $"{cleanTitle.ToLowerInvariant()}_{cleanMsg.ToLowerInvariant()}";

                var now = DateTime.UtcNow;
                int cooldownSeconds = isThreatLike ? 1800 : 180;
                if (_recentNotificationCache.TryGetValue(cacheKey, out var lastTime) && (now - lastTime).TotalSeconds < cooldownSeconds)
                {
                    return;
                }
                _recentNotificationCache[cacheKey] = now;

                // Periodically prune stale cache entries (older than 60 minutes)
                if (_recentNotificationCache.Count > 50)
                {
                    foreach (var kvp in _recentNotificationCache.ToArray())
                    {
                        if ((now - kvp.Value).TotalMinutes > 60)
                        {
                            _recentNotificationCache.TryRemove(kvp.Key, out _);
                        }
                    }
                }

                if (isThreatLike)
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
                var settings = _settingsService ?? (App.ServiceProvider?.GetService(typeof(ISettingsService)) as ISettingsService);
                if (settings != null && !settings.GetSetting("NotificationsEnabled", true))
                {
                    while (_threatQueue.TryDequeue(out _)) { }
                    return;
                }

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
                    bool hasQuarantined = items.Any(i => i.Type.Equals("Danger", StringComparison.OrdinalIgnoreCase) ||
                                                         i.Type.Equals("Error", StringComparison.OrdinalIgnoreCase) ||
                                                         i.Title.Contains("Karantina", StringComparison.OrdinalIgnoreCase) ||
                                                         i.Message.Contains("karantina", StringComparison.OrdinalIgnoreCase) ||
                                                         i.Message.Contains("kilitlendi", StringComparison.OrdinalIgnoreCase));

                    var now = DateTime.UtcNow;
                    string batchKey = hasQuarantined ? "batch_threat_quarantined" : "batch_threat_warning";
                    if (_recentNotificationCache.TryGetValue(batchKey, out var lastBatch) && (now - lastBatch).TotalMinutes < 15)
                    {
                        return;
                    }
                    _recentNotificationCache[batchKey] = now;

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

                    if (hasQuarantined)
                    {
                        string summaryTitle = $"Ultron Defender (Antivirüs Programı) - 🛡️ {count} Tehdit Engellendi ve Karantinaya Alındı";
                        string summaryMessage = $"{count} adet zararlı tehdit tespit edildi ve sisteminizden temizlenerek AES-256 Karantina Kasasına kilitlendi.\n({sampleList}{(items.Count > 3 ? "..." : "")})\nDetaylar için Güvenlik Merkezini açın.";
                        EmitNativeToast(summaryTitle, summaryMessage, "Danger");
                    }
                    else
                    {
                        string summaryTitle = $"Ultron Defender (Antivirüs Programı) - ⚠️ {count} Şüpheli Olay / Dosya Algılandı";
                        string summaryMessage = $"{count} adet şüpheli dosya veya davranış tespit edildi. Dosyalar silinmedi, incelemeniz için Olay Geçmişine kaydedildi.\n({sampleList}{(items.Count > 3 ? "..." : "")})\nDetaylar için Olay Geçmişini açın.";
                        EmitNativeToast(summaryTitle, summaryMessage, "Warning");
                    }
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
