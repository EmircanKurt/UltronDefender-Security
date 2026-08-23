using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Notifications
{
    public class NotificationAggregator : INotificationAggregator, IDisposable
    {
        private readonly IWindowsToastNotificationService _toastService;
        private readonly ILogger<NotificationAggregator>? _logger;
        private readonly ConcurrentQueue<AggregatedThreatItem> _queue = new();
        private readonly Timer _aggregationTimer;
        private int _isFlushing;

        public TimeSpan AggregationWindow { get; set; } = TimeSpan.FromSeconds(3);

        public NotificationAggregator(
            IWindowsToastNotificationService toastService,
            ILogger<NotificationAggregator>? logger = null)
        {
            _toastService = toastService;
            _logger = logger;
            _aggregationTimer = new Timer(OnTimerTick, null, Timeout.Infinite, Timeout.Infinite);
        }

        public void PushThreatEvent(string threatName, string objectPath, string actionTaken, bool isCritical = false)
        {
            _queue.Enqueue(new AggregatedThreatItem
            {
                ThreatName = threatName,
                ObjectPath = objectPath,
                ActionTaken = actionTaken,
                IsCritical = isCritical,
                Timestamp = DateTime.UtcNow
            });

            // Kayan pencere (Sliding Debounce): Seri halde düşen tehditleri tek bir toplu bildirimde birleştirir
            int windowMs = isCritical ? 200 : (int)AggregationWindow.TotalMilliseconds;
            _aggregationTimer.Change(windowMs, Timeout.Infinite);
        }

        private void OnTimerTick(object? state)
        {
            Flush();
        }

        public void Flush()
        {
            if (Interlocked.Exchange(ref _isFlushing, 1) == 1) return;

            try
            {
                var items = new List<AggregatedThreatItem>();
                while (_queue.TryDequeue(out var item))
                {
                    items.Add(item);
                }

                if (items.Count == 0) return;

                if (items.Count == 1)
                {
                    var single = items[0];
                    string prefix = single.IsCritical ? "🚨 KRİTİK GÜVENLİK TEHDİDİ ENGELLENDİ" : "🛡️ Tehdit Etkisiz Hale Getirildi";
                    string type = single.IsCritical ? "danger" : "warning";
                    _toastService.ShowToast(
                        $"Ultron Defender (Antivirüs Programı) - {prefix}",
                        $"{single.ThreatName} ({single.ActionTaken})\nKonum: {single.ObjectPath}",
                        type);
                }
                else
                {
                    int quarantined = items.Count(i => i.ActionTaken.Contains("Karantina", StringComparison.OrdinalIgnoreCase) || i.ActionTaken.Contains("Quarantine", StringComparison.OrdinalIgnoreCase));
                    int blocked = items.Count - quarantined;
                    bool hasCritical = items.Any(i => i.IsCritical);

                    string sampleNames = string.Join(", ", items.Select(i => i.ThreatName).Distinct().Take(3));

                    _toastService.ShowToast(
                        $"Ultron Defender (Antivirüs Programı) - 🛡️ {items.Count} Güvenlik Tehdidi Etkisiz Hale Getirildi",
                        $"{items.Count} adet tehdit engellendi ({quarantined} karantinaya alındı, {blocked} işlem durduruldu).\n({sampleNames}{(items.Count > 3 ? "..." : "")})\nDetaylar için Güvenlik Merkezini açın.",
                        hasCritical ? "danger" : "warning");
                }
            }
            finally
            {
                Interlocked.Exchange(ref _isFlushing, 0);
            }
        }

        public void Dispose()
        {
            _aggregationTimer.Dispose();
            Flush();
        }

        private record AggregatedThreatItem
        {
            public string ThreatName { get; init; } = string.Empty;
            public string ObjectPath { get; init; } = string.Empty;
            public string ActionTaken { get; init; } = string.Empty;
            public bool IsCritical { get; init; }
            public DateTime Timestamp { get; init; }
        }
    }
}
