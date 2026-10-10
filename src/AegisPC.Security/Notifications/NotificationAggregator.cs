using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Notifications
{
    /// <summary>
    /// Groups distinct recorded security events while preserving source action text.
    /// The legacy string contract cannot prove quarantine, blocking, or malware confirmation.
    /// </summary>
    public class NotificationAggregator : INotificationAggregator, IDisposable
    {
        private readonly IWindowsToastNotificationService _toastService;
        private readonly ILogger<NotificationAggregator>? _logger;
        private readonly object _queueLock = new();
        private readonly Dictionary<EventKey, AggregatedThreatItem> _queue = new();
        private readonly Timer _aggregationTimer;
        private readonly bool _enableAggregationTimer;
        private TimeSpan _aggregationWindow = TimeSpan.FromSeconds(3);
        private int _isFlushing;
        private bool _disposed;

        /// <summary>
        /// Gets or sets the positive debounce window for noncritical events.
        /// Values outside the supported timer millisecond range are rejected.
        /// </summary>
        public TimeSpan AggregationWindow
        {
            get => _aggregationWindow;
            set
            {
                if (value <= TimeSpan.Zero || value.TotalMilliseconds > int.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(value));
                _aggregationWindow = value;
            }
        }

        /// <summary>
        /// Creates an event aggregator. Disabling its timer allows explicit deterministic
        /// flushing; the default continues to debounce production notifications.
        /// </summary>
        public NotificationAggregator(
            IWindowsToastNotificationService toastService,
            ILogger<NotificationAggregator>? logger = null,
            bool enableAggregationTimer = true)
        {
            _toastService = toastService ?? throw new ArgumentNullException(nameof(toastService));
            _logger = logger;
            _enableAggregationTimer = enableAggregationTimer;
            _aggregationTimer = new Timer(OnTimerTick, null, Timeout.Infinite, Timeout.Infinite);
        }

        /// <summary>
        /// Queues source event facts. Repeated name/path/action tuples count once per batch;
        /// critical severity never implies that an action succeeded. Disposed calls are ignored.
        /// </summary>
        public void PushThreatEvent(string threatName, string objectPath, string actionTaken, bool isCritical = false)
        {
            lock (_queueLock)
            {
                if (_disposed) return;
                var key = new EventKey(threatName ?? string.Empty, objectPath ?? string.Empty, actionTaken ?? string.Empty);
                if (_queue.TryGetValue(key, out var previous)) isCritical |= previous.IsCritical;
                _queue[key] = new AggregatedThreatItem(key.ThreatName, key.ObjectPath, key.ActionTaken, isCritical);

                if (_enableAggregationTimer)
                {
                    var window = _queue.Values.Any(i => i.IsCritical) ? TimeSpan.FromMilliseconds(200) : AggregationWindow;
                    _aggregationTimer.Change(window, Timeout.InfiniteTimeSpan);
                }
            }
        }

        private void OnTimerTick(object? state) => Flush();

        /// <summary>
        /// Emits unique queued events as source records, not inferred malware or successful
        /// actions. Empty or disposed instances do not emit; presentation failures are logged.
        /// </summary>
        public void Flush()
        {
            if (Volatile.Read(ref _disposed) || Interlocked.Exchange(ref _isFlushing, 1) == 1) return;
            try
            {
                AggregatedThreatItem[] items;
                lock (_queueLock)
                {
                    if (_disposed) return;
                    items = _queue.Values.ToArray();
                    _queue.Clear();
                }
                if (items.Length == 0 || Volatile.Read(ref _disposed)) return;

                bool critical = items.Any(i => i.IsCritical);
                string title = items.Length == 1
                    ? critical ? "KRİTİK GÜVENLİK OLAYI" : "Güvenlik olayı"
                    : $"{items.Length} güvenlik olayı";
                string message = string.Join("\n\n", items.Take(3).Select(i =>
                    $"{i.ThreatName}\nKaynak işlem kaydı: {i.ActionTaken}\nKonum: {i.ObjectPath}"));
                if (items.Length > 3) message += $"\n\n{items.Length - 3} ek olay bu özette gösterilmedi.";

                _toastService.ShowToast(title, message, critical ? "danger" : "warning");
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to flush security event notifications");
            }
            finally
            {
                Interlocked.Exchange(ref _isFlushing, 0);
            }
        }

        /// <summary>
        /// Drops pending events and stops future emissions without a shutdown toast.
        /// An emission already passed downstream cannot be recalled by this aggregator.
        /// </summary>
        public void Dispose()
        {
            lock (_queueLock)
            {
                if (_disposed) return;
                Volatile.Write(ref _disposed, true);
                _queue.Clear();
                _aggregationTimer.Dispose();
            }
        }

        private readonly record struct EventKey(string ThreatName, string ObjectPath, string ActionTaken);
        private sealed record AggregatedThreatItem(string ThreatName, string ObjectPath, string ActionTaken, bool IsCritical);
    }
}
