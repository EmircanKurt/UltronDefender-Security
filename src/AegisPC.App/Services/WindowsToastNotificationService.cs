using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.App.Services
{
    /// <summary>
    /// Deduplicates and groups notifications without turning severity or text into detection
    /// or quarantine evidence. Group counts describe notifications, not malicious files.
    /// </summary>
    public class WindowsToastNotificationService : IWindowsToastNotificationService, IDisposable
    {
        private readonly ILogger<WindowsToastNotificationService>? _logger;
        private readonly ISettingsService? _settingsService;
        private readonly Action<string, string, string>? _notificationSink;
        private readonly bool _enableAggregationTimer;
        private readonly object _queueLock = new();
        private readonly Queue<ThreatToastItem> _threatQueue = new();
        private readonly Dictionary<NotificationKey, DateTime> _recentNotificationCache = new();
        private readonly Timer _aggregationTimer;
        private TimeSpan _aggregationWindow = TimeSpan.FromMilliseconds(2500);
        private int _isFlushing;
        private bool _disposed;

        /// <summary>
        /// Gets or sets the positive debounce interval for warning and error notifications.
        /// Intervals exceeding the supported timer millisecond range are rejected.
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
        /// Creates a notification service. The optional sink replaces native presentation;
        /// disabling the timer permits deterministic flushing without UI windows.
        /// </summary>
        public WindowsToastNotificationService(
            ISettingsService? settingsService = null,
            ILogger<WindowsToastNotificationService>? logger = null,
            Action<string, string, string>? notificationSink = null,
            bool enableAggregationTimer = true)
        {
            _settingsService = settingsService;
            _logger = logger;
            _notificationSink = notificationSink;
            _enableAggregationTimer = enableAggregationTimer;
            _aggregationTimer = new Timer(OnTimerTick, null, Timeout.Infinite, Timeout.Infinite);
        }

        /// <summary>
        /// Presents source content or queues it for a neutral summary. Exact duplicates are
        /// cooled down atomically; digits in paths and source outcomes remain intact.
        /// Disabled notifications and calls after disposal are ignored.
        /// </summary>
        public void ShowToast(string title, string message, string type = "Info")
        {
            try
            {
                if (Volatile.Read(ref _disposed) || !AreNotificationsEnabled()) return;
                title ??= string.Empty;
                message ??= string.Empty;
                type = string.IsNullOrWhiteSpace(type) ? "Info" : type;
                bool deferred = IsWarningOrError(type);
                if (!deferred && IsRoutineMaintenance(title, message)) return;
                lock (_queueLock)
                {
                    if (_disposed || !ReserveNotification(title, message, type, deferred)) return;
                    if (deferred)
                    {
                        _threatQueue.Enqueue(new ThreatToastItem(title, message, type));
                        if (_enableAggregationTimer)
                            _aggregationTimer.Change(AggregationWindow, Timeout.InfiniteTimeSpan);
                    }
                }

                if (!deferred) EmitNativeToast(title, message, type);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to enqueue a notification");
            }
        }

        private bool ReserveNotification(string title, string message, string type, bool deferred)
        {
            var key = new NotificationKey(type.ToUpperInvariant(), title, message);
            var now = DateTime.UtcNow;
            var cooldown = TimeSpan.FromMinutes(deferred ? 30 : 3);
            if (_recentNotificationCache.TryGetValue(key, out var lastTime) && now - lastTime < cooldown)
                return false;

            foreach (var stale in _recentNotificationCache.Where(p => now - p.Value >= TimeSpan.FromHours(1)).Select(p => p.Key).ToArray())
                _recentNotificationCache.Remove(stale);
            if (_recentNotificationCache.Count >= 1024)
                _recentNotificationCache.Remove(_recentNotificationCache.MinBy(p => p.Value).Key);
            _recentNotificationCache[key] = now;
            return true;
        }

        private bool AreNotificationsEnabled()
        {
            var settings = _settingsService ?? (App.ServiceProvider?.GetService(typeof(ISettingsService)) as ISettingsService);
            return settings == null || settings.GetSetting("NotificationsEnabled", true);
        }

        private static bool IsWarningOrError(string type) =>
            type.Equals("Warning", StringComparison.OrdinalIgnoreCase) ||
            type.Equals("Error", StringComparison.OrdinalIgnoreCase) ||
            type.Equals("Danger", StringComparison.OrdinalIgnoreCase);

        private static bool IsRoutineMaintenance(string title, string message) =>
            title.Contains("Rutin Tarama", StringComparison.OrdinalIgnoreCase) ||
            title.Contains("Günlük Tam Tarama Başlatılıyor", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("20 dakikalık", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("planlanmış tam tarama henüz yapılmadığından", StringComparison.OrdinalIgnoreCase);

        private void OnTimerTick(object? state) => FlushThreats();

        private void FlushThreats()
        {
            if (Volatile.Read(ref _disposed) || Interlocked.Exchange(ref _isFlushing, 1) == 1) return;
            try
            {
                ThreatToastItem[] items;
                lock (_queueLock)
                {
                    if (_disposed) return;
                    items = _threatQueue.ToArray();
                    _threatQueue.Clear();
                }

                if (items.Length == 0 || !AreNotificationsEnabled()) return;
                if (items.Length == 1)
                {
                    var single = items[0];
                    EmitNativeToast(single.Title, single.Message, single.Type);
                    return;
                }

                // Severity changes appearance only; the string API proves no action outcome.
                string type = items.Any(i => i.Type.Equals("Danger", StringComparison.OrdinalIgnoreCase)) ? "Danger"
                    : items.Any(i => i.Type.Equals("Error", StringComparison.OrdinalIgnoreCase)) ? "Error" : "Warning";
                string details = string.Join("\n\n", items.Take(3).Select(i => $"{i.Title}\n{i.Message}"));
                if (items.Length > 3) details += $"\n\n{items.Length - 3} ek bildirim bu özette gösterilmedi.";
                EmitNativeToast($"{items.Length} bildirim", details, type);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to flush queued notifications");
            }
            finally
            {
                Interlocked.Exchange(ref _isFlushing, 0);
            }
        }

        private static string FormatAppHeader(string title)
        {
            // The notification card already displays the application brand separately.
            return string.IsNullOrWhiteSpace(title) ? "Ultron bildirimi" : title;
        }

        private void EmitNativeToast(string title, string message, string type)
        {
            if (Volatile.Read(ref _disposed)) return;
            try
            {
                _logger?.LogInformation("Windows notification [{Type}]: {Title} - {Message}", type, title, message);
                string fullTitle = FormatAppHeader(title);
                // Native dispatch must not hold the queue lock, avoiding a UI shutdown deadlock.
                if (_notificationSink != null) _notificationSink(fullTitle, message, type);
                else Views.ToastNotificationWindow.ShowToast(fullTitle, message, type);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to present a notification");
            }
        }

        /// <summary>
        /// Stops aggregation and drops pending messages without displaying shutdown toasts.
        /// An emission already handed to the UI cannot be recalled by this service.
        /// </summary>
        public void Dispose()
        {
            lock (_queueLock)
            {
                if (_disposed) return;
                Volatile.Write(ref _disposed, true);
                _threatQueue.Clear();
                _recentNotificationCache.Clear();
                _aggregationTimer.Dispose();
            }
        }

        private readonly record struct NotificationKey(string Type, string Title, string Message);
        private sealed record ThreatToastItem(string Title, string Message, string Type);
    }
}
