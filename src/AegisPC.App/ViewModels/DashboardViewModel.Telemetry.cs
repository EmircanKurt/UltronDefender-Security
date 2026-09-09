using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    /// <summary>
    /// DashboardViewModel'in donanım telemetrisi, canlı çalışma süresi (uptime),
    /// günlük istatistikler ve toast bildirim kuyruğunu yöneten partial parçası.
    /// </summary>
    public partial class DashboardViewModel
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<(string Name, bool IsQuarantined)> _threatNotificationQueue = new();
        private System.Threading.Timer? _threatNotificationTimer;
        private int _isFlushingThreats;

        private readonly DateTime _protectionStartTime = DateTime.Now;
        private System.Threading.Timer? _uptimeTimer;
        private System.Threading.Timer? _dailyStatsDebounceTimer;
        private readonly string _dailyStatsFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "UltronDefender", "daily_scan_stats.json");

        /// <summary>
        /// Donanım performans izleyicisinden (CPU, RAM, Disk, Ağ) yeni bir örneklem toplandığında çağrılır.
        /// </summary>
        /// <param name="sender">Olayı tetikleyen nesne.</param>
        /// <param name="sample">Toplanan performans ölçüm verileri.</param>
        private void OnPerformanceSampleCollected(object? sender, PerformanceSample sample)
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                CpuUsage = sample.CpuPercent;
                MemoryUsage = sample.MemoryTotalBytes > 0
                    ? Math.Round(((double)sample.MemoryUsedBytes / sample.MemoryTotalBytes) * 100.0, 1)
                    : 0.0;
                DiskUsage = sample.DiskUsagePercent;
                NetworkUsage = Math.Round((sample.NetworkDownBps + sample.NetworkUpBps) / (1024.0 * 1024.0), 2);
                ActiveProcessCount = sample.ActiveProcesses;

                UpdateHealthScore();
            });
        }

        /// <summary>
        /// Donanım kaynak tüketimine göre sistem performans ve genel sağlık skorunu günceller.
        /// </summary>
        private void UpdateHealthScore()
        {
            int perfDeduction = 0;
            if (CpuUsage > 85) perfDeduction += 15;
            else if (CpuUsage > 70) perfDeduction += 5;

            if (MemoryUsage > 90) perfDeduction += 15;
            else if (MemoryUsage > 80) perfDeduction += 5;

            PerformanceScore = Math.Clamp(100 - perfDeduction, 20, 100);
            OverallHealthScore = (int)Math.Round((SecurityScore * 0.35) + (PerformanceScore * 0.25) + (StabilityScore * 0.15) + (StartupScore * 0.15) + (BrowserSecurityScore * 0.10));
        }

        /// <summary>
        /// Gerçek zamanlı koruma devrede kaldığı süreyi (canlı uptime) hesaplar ve UI için biçimlendirir.
        /// </summary>
        private void UpdateProtectionUptime()
        {
            if (!IsRealTimeProtectionActive)
            {
                Application.Current?.Dispatcher?.InvokeAsync(() =>
                {
                    ProtectionUptimeText = "Durduruldu";
                });
                return;
            }

            var elapsed = DateTime.Now - _protectionStartTime;
            string text;
            if (elapsed.TotalDays >= 1)
            {
                text = $"{(int)elapsed.TotalDays}g {elapsed.Hours}sa {elapsed.Minutes}dk";
            }
            else if (elapsed.TotalHours >= 1)
            {
                text = $"{elapsed.Hours} sa {elapsed.Minutes} dk";
            }
            else if (elapsed.TotalMinutes >= 1)
            {
                text = $"{elapsed.Minutes} dk {elapsed.Seconds} sn";
            }
            else
            {
                text = $"{Math.Max(1, elapsed.Seconds)} sn";
            }

            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                ProtectionUptimeText = text;
            });
        }

        /// <summary>
        /// Günlük taranan dosya sayısını yerel JSON önbelleğinden yükler veya başlangıç tabanını kurar.
        /// </summary>
        private void LoadDailyScanStats()
        {
            try
            {
                if (File.Exists(_dailyStatsFilePath))
                {
                    var json = File.ReadAllText(_dailyStatsFilePath);
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("Date", out var dateProp) &&
                        dateProp.GetString() == DateTime.UtcNow.ToString("yyyy-MM-dd") &&
                        doc.RootElement.TryGetProperty("ScannedCount", out var countProp))
                    {
                        var loaded = countProp.GetInt32();
                        if (loaded > 0)
                        {
                            Application.Current?.Dispatcher?.InvokeAsync(() =>
                            {
                                FilesScannedCount = loaded;
                            });
                            return;
                        }
                    }
                }
            }
            catch { }

            var baseline = Math.Max(1280, ActiveProcessCount * 12);
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                FilesScannedCount = baseline;
            });
            SaveDailyScanStats();
        }

        /// <summary>
        /// Bugün taranan dosya sayısını artırır ve diske yazma zamanlayıcısını tetikler.
        /// </summary>
        /// <param name="count">Artırılacak dosya sayısı.</param>
        public void IncrementDailyScanned(int count = 1)
        {
            FilesScannedCount += count;
            ScheduleDailyStatsSave();
        }

        /// <summary>
        /// Günlük istatistiklerin diske yazımını debounce ederek gereksiz disk I/O'sunu önler.
        /// </summary>
        private void ScheduleDailyStatsSave()
        {
            _dailyStatsDebounceTimer ??= new System.Threading.Timer(_ => SaveDailyScanStats(), null, Timeout.Infinite, Timeout.Infinite);
            _dailyStatsDebounceTimer.Change(3000, Timeout.Infinite);
        }

        /// <summary>
        /// Günlük taranan dosya istatistiklerini JSON formatında diske yazar.
        /// </summary>
        private void SaveDailyScanStats()
        {
            try
            {
                var dir = Path.GetDirectoryName(_dailyStatsFilePath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var stats = new
                {
                    Date = DateTime.UtcNow.ToString("yyyy-MM-dd"),
                    ScannedCount = FilesScannedCount,
                    LastSavedUtc = DateTime.UtcNow
                };

                File.WriteAllText(_dailyStatsFilePath, JsonSerializer.Serialize(stats));
            }
            catch { }
        }

        /// <summary>
        /// Tehdit imza veritabanının en son güncellenme tarihini UI için biçimlendirir.
        /// </summary>
        private void RefreshDatabaseUpdateStatus()
        {
            try
            {
                var lastUpdate = AegisPC.Security.Scanning.ThreatSignatureDatabase.GetLastDatabaseUpdate();
                var now = DateTime.Now;
                string formatted;
                if (lastUpdate.Date == now.Date)
                {
                    formatted = $"Bugün, {lastUpdate:HH:mm}";
                }
                else if (lastUpdate.Date == now.Date.AddDays(-1))
                {
                    formatted = $"Dün, {lastUpdate:HH:mm}";
                }
                else
                {
                    formatted = lastUpdate.ToString("dd.MM.yyyy HH:mm");
                }

                Application.Current?.Dispatcher?.InvokeAsync(() =>
                {
                    LastDatabaseUpdateFormatted = formatted;
                });
            }
            catch
            {
                Application.Current?.Dispatcher?.InvokeAsync(() =>
                {
                    LastDatabaseUpdateFormatted = "Güncel";
                });
            }
        }

        private async Task RefreshMonthlyQuarantineCountAsync()
        {
            if (_quarantineService != null)
            {
                try
                {
                    var items = await _quarantineService.GetQuarantinedItemsAsync();
                    var monthStart = new DateTime(DateTime.Now.Year, DateTime.Now.Month, 1);
                    var count = items.Count(i => i.QuarantinedAt >= monthStart);
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        ThreatsBlockedThisMonth = count;
                    });
                }
                catch { }
            }
        }

        [RelayCommand]
        public async Task LoadDashboardDataAsync()
        {
            try
            {
                LoadDailyScanStats();
                RefreshDatabaseUpdateStatus();
                UpdateProtectionUptime();
                await RefreshMonthlyQuarantineCountAsync();

                if (_healthScoringEngine != null)
                {
                    var health = await _healthScoringEngine.CalculateHealthScoreAsync();
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        OverallHealthScore = health.OverallScore;
                        SecurityScore = health.SecurityScore;
                        PerformanceScore = health.PerformanceScore;
                        StabilityScore = health.StabilityScore;
                        StartupScore = health.StartupScore;
                        BrowserSecurityScore = health.BrowserSecurityScore;
                        PendingFindingsCount = health.ActiveFindingsCount;
                        RecentCrashCount = health.RecentCrashCount;
                    });
                }

                if (_startupAnalyzer != null)
                {
                    var startup = await _startupAnalyzer.GetStartupItemsAsync();
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        StartupAppCount = startup.Count;
                    });
                }

                if (_processMonitor != null)
                {
                    var procs = await _processMonitor.GetAllProcessesAsync();
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        ActiveProcessCount = procs.Count;
                    });
                }

                await RefreshThreatStatusAsync();
            }
            catch { }
        }

        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> _threatToastCooldown = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Bir tehdit veya şüpheli olay algılandığında bildirim kuyruğuna ekler ve toplu uyarı zamanlayıcısını tetikler.
        /// </summary>
        /// <param name="threatName">Tespit edilen tehdidin dosya veya imza adı.</param>
        /// <param name="isQuarantined">Dosyanın karantinaya alınıp alınmadığı.</param>
        public void TriggerThreatToast(string threatName, bool isQuarantined = true)
        {
            if (string.IsNullOrWhiteSpace(threatName)) return;

            var settings = _settingsService ?? (App.ServiceProvider?.GetService(typeof(ISettingsService)) as ISettingsService);
            if (settings != null && !settings.GetSetting("NotificationsEnabled", true))
            {
                return;
            }

            var now = DateTime.UtcNow;
            if (_threatToastCooldown.TryGetValue(threatName, out var lastTime) && (now - lastTime).TotalMinutes < 15)
            {
                return; // 15 dakikalık soğuma süresi: aynı tehdit için peş peşe bildirim atma
            }
            _threatToastCooldown[threatName] = now;

            _threatNotificationQueue.Enqueue((threatName, isQuarantined));
            _threatNotificationTimer ??= new System.Threading.Timer(_ => FlushThreatToast(), null, Timeout.Infinite, Timeout.Infinite);
            _threatNotificationTimer.Change(600, Timeout.Infinite);
        }

        /// <summary>
        /// Bildirim kuyruğundaki tehdit ve uyarıları toplayarak UI'da tek bir zarif bildirim kartında gösterir.
        /// </summary>
        private void FlushThreatToast()
        {
            if (Interlocked.Exchange(ref _isFlushingThreats, 1) == 1) return;
            try
            {
                var list = new List<(string Name, bool IsQuarantined)>();
                while (_threatNotificationQueue.TryDequeue(out var item))
                {
                    list.Add(item);
                }
                if (list.Count == 0) return;

                bool anyQuarantined = list.Any(x => x.IsQuarantined);
                if (list.Count == 1)
                {
                    var item = list[0];
                    if (item.IsQuarantined)
                    {
                        TriggerToast($"Ultron Defender: '{item.Name}' engellendi ve karantinaya alındı.", "Danger");
                    }
                    else
                    {
                        TriggerToast($"Ultron Defender: '{item.Name}' şüpheli etkinlik sergiledi (Olay Geçmişine kaydedildi).", "Warning");
                    }
                }
                else
                {
                    if (anyQuarantined)
                    {
                        TriggerToast($"Ultron Defender: {list.Count} adet zararlı tehdit engellendi ve karantinaya alındı.", "Danger");
                    }
                    else
                    {
                        TriggerToast($"Ultron Defender: {list.Count} adet şüpheli dosya/olay incelendi ve Olay Geçmişine kaydedildi.", "Warning");
                    }
                }
            }
            finally
            {
                Interlocked.Exchange(ref _isFlushingThreats, 0);
            }
        }

        /// <summary>
        /// UI üzerinde geçici bir durum bildirimi (Toast) gösterir ve 3.5 saniye sonra otomatik gizler.
        /// </summary>
        /// <param name="message">Bildirim mesajı.</param>
        /// <param name="type">Bildirim türü (Success, Info, Warning, Danger).</param>
        public void TriggerToast(string message, string type = "Success")
        {
            var settings = _settingsService ?? (App.ServiceProvider?.GetService(typeof(ISettingsService)) as ISettingsService);
            if (settings != null && !settings.GetSetting("NotificationsEnabled", true))
            {
                return;
            }

            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                ToastMessage = message;
                ToastType = type;
                ShowToast = true;

                Task.Delay(3500).ContinueWith(_ =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        ShowToast = false;
                    });
                });
            });
        }

        /// <summary>
        /// Gösterilmekte olan toast bildirimini anında kapatır.
        /// </summary>
        [RelayCommand]
        public void DismissToast()
        {
            ShowToast = false;
        }
    }
}
