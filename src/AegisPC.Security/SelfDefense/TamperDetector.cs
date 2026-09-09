using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.SelfDefense
{
    /// <summary>
    /// AegisPC Bütünleşik Müdahale Tespit ve Önleme Motoru (Anti-Tampering Engine).
    /// Sysmon Event ID 1 ve Windows Security Event ID 4688 olaylarını dinler;
    /// sc config, reg add, del, fltmc unload ve Process Hacker aktivitelerini tespit eder.
    /// Tespit anında otomatik olarak:
    /// 1. Saldırgan süreci sonlandırır (Process Kill).
    /// 2. Yüksek öncelikli güvenlik alarmı (SecurityFinding) üretir.
    /// 3. Devre dışı bırakılmak istenen servis, sürücü veya anahtarı eski haline döndürür (Self-Heal).
    /// </summary>
    public class TamperDetector : IDisposable
    {
        private readonly EventLogReader _eventLogReader;
        private readonly ISecurityFindingService? _findingService;
        private readonly SelfHealManager _selfHealManager;
        private readonly ILogger<TamperDetector>? _logger;

        private bool _isAutoContainmentEnabled = true;
        private bool _isRunning;
        private readonly object _lock = new();

        public bool IsAutoContainmentEnabled
        {
            get => _isAutoContainmentEnabled;
            set => _isAutoContainmentEnabled = value;
        }

        public bool IsRunning => _isRunning;

        public event Action<TamperAlert>? TamperDetected;

        public TamperDetector(
            EventLogReader eventLogReader,
            SelfHealManager? selfHealManager = null,
            ISecurityFindingService? findingService = null,
            ILogger<TamperDetector>? logger = null)
        {
            _eventLogReader = eventLogReader;
            _selfHealManager = selfHealManager ?? new SelfHealManager();
            _findingService = findingService;
            _logger = logger;

            _eventLogReader.ProcessCreated += OnProcessCreated;
        }

        public void Start()
        {
            lock (_lock)
            {
                if (_isRunning) return;

                _eventLogReader.StartListening();
                SelfDefenseManager.ProtectCurrentProcess();
                _isRunning = true;
                _logger?.LogInformation("TamperDetector motoru başlatıldı (Auto-Containment: {Enabled}).", _isAutoContainmentEnabled);
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (!_isRunning) return;

                _eventLogReader.StopListening();
                _isRunning = false;
                _logger?.LogInformation("TamperDetector motoru durduruldu.");
            }
        }

        private void OnProcessCreated(ProcessCreationEvent evt)
        {
            if (evt == null) return;

            // Kendi süreçlerimizin meşru eylemlerini hariç tut
            if (IsLegitimateAegisProcess(evt.ProcessId, evt.ImagePath))
            {
                return;
            }

            if (CheckTamperPattern(evt.ImagePath, evt.CommandLine, out var tamperType, out var targetAsset, out var ruleName))
            {
                _ = HandleTamperDetectedAsync(evt, tamperType, targetAsset, ruleName);
            }
        }

        public async Task<TamperAlert> HandleTamperDetectedAsync(
            ProcessCreationEvent evt,
            TamperType tamperType,
            string targetAsset,
            string ruleName)
        {
            _logger?.LogWarning("🚨 ANTI-TAMPER TESPİT EDİLDİ! Kural: {Rule}, PID: {PID}, Görsel: {Image}, Komut: {Cmd}",
                ruleName, evt.ProcessId, evt.ImagePath, evt.CommandLine);

            bool isContained = false;
            bool isSelfHealed = false;
            string healingDetails = string.Empty;

            // 1. Otomatik İzolasyon (Auto-Containment): Saldırgan Süreci Derhal Kapat
            if (_isAutoContainmentEnabled && evt.ProcessId > 4)
            {
                isContained = TerminateOffendingProcess(evt.ProcessId, evt.ImagePath);
            }

            // 2. Kendi Kendini Onarma (Self-Heal)
            switch (tamperType)
            {
                case TamperType.ServiceConfigTamper:
                case TamperType.RegistryTamper:
                    isSelfHealed = _selfHealManager.HealService(SelfHealManager.DefaultServiceName);
                    healingDetails = "Servis başlangıç tipi Automatic olarak düzeltildi ve servis başlatıldı";
                    break;

                case TamperType.DriverUnloadTamper:
                    isSelfHealed = _selfHealManager.HealMinifilterDriver(SelfHealManager.DefaultDriverName);
                    healingDetails = "AegisFilter minifilter sürücüsü yeniden yüklendi";
                    break;

                case TamperType.BinaryDeletionTamper:
                    SelfDefenseManager.ProtectCurrentProcess();
                    isSelfHealed = true;
                    healingDetails = "Yürütülebilir dosya kilidi ve ACL koruması tazelendi";
                    break;
            }

            // 3. Alarm Oluşturma ve Olay Fırlatma
            var alert = new TamperAlert
            {
                OffendingProcessId = evt.ProcessId,
                OffendingImagePath = evt.ImagePath,
                OffendingCommandLine = evt.CommandLine,
                TargetAsset = targetAsset,
                TamperType = tamperType,
                DetectionRule = ruleName,
                IsContained = isContained,
                IsSelfHealed = isSelfHealed,
                HealingDetails = healingDetails,
                TimestampUtc = evt.TimestampUtc
            };

            try
            {
                TamperDetected?.Invoke(alert);
            }
            catch { }

            // 4. Güvenlik Motoruna Bildirim (ISecurityFindingService)
            if (_findingService != null)
            {
                try
                {
                    var finding = alert.ToSecurityFinding();
                    await _findingService.AddFindingAsync(finding);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "SecurityFinding eklenirken hata oluştu.");
                }
            }

            return alert;
        }

        /// <summary>
        /// Gelen komut satırı ve görsel yolunun bir Anti-Tamper saldırısı olup olmadığını statik olarak analiz eder.
        /// </summary>
        public static bool CheckTamperPattern(
            string imagePath,
            string commandLine,
            out TamperType tamperType,
            out string targetAsset,
            out string ruleName)
        {
            tamperType = TamperType.None;
            targetAsset = string.Empty;
            ruleName = string.Empty;

            if (string.IsNullOrWhiteSpace(commandLine) && string.IsNullOrWhiteSpace(imagePath))
            {
                return false;
            }

            string cmd = (commandLine ?? string.Empty).ToLowerInvariant();
            string img = Path.GetFileName(imagePath ?? string.Empty).ToLowerInvariant();

            // KURAL 1: fltmc unload AegisFilter (Minifilter Boşaltma Girişimi)
            if (cmd.Contains("fltmc") && cmd.Contains("unload") && (cmd.Contains("aegis") || cmd.Contains("ultron")))
            {
                tamperType = TamperType.DriverUnloadTamper;
                targetAsset = "AegisFilter (Kernel Minifilter Driver)";
                ruleName = "TAMPER-01: Fltmc Unload Sürücü Boşaltma Girişimi";
                return true;
            }

            // KURAL 2: sc config AegisPCProtectionService start= disabled (Servis Devre Dışı Bırakma / Silme)
            if ((cmd.Contains("sc") || cmd.Contains("sc.exe")) && 
                (cmd.Contains("config") || cmd.Contains("stop") || cmd.Contains("delete")) &&
                (cmd.Contains("aegis") || cmd.Contains("ultron")))
            {
                if (cmd.Contains("disabled") || cmd.Contains("stop") || cmd.Contains("delete") || cmd.Contains("start="))
                {
                    tamperType = TamperType.ServiceConfigTamper;
                    targetAsset = "AegisPCProtectionService (Windows Service)";
                    ruleName = "TAMPER-02: SC Config/Stop/Delete Servis Müdahalesi";
                    return true;
                }
            }

            // KURAL 3: reg add HKLM\SYSTEM\CurrentControlSet\Services\Aegis* /v Start /d 4 (Kayıt Defteri Start=4 Girişimi)
            if ((cmd.Contains("reg") || cmd.Contains("reg.exe")) &&
                (cmd.Contains(@"services\aegis") || cmd.Contains(@"services\ultron")) &&
                (cmd.Contains("/d 4") || cmd.Contains("/d \"4\"") || cmd.Contains("delete")))
            {
                tamperType = TamperType.RegistryTamper;
                targetAsset = "HKLM\\SYSTEM\\CurrentControlSet\\Services (Service Registry Key)";
                ruleName = "TAMPER-03: Registry Start=4 Servis Felç Etme Girişimi";
                return true;
            }

            // KURAL 4: del /f /q "AegisPC.exe" veya UltronDefender dosyalarını silme
            if ((cmd.Contains("del ") || cmd.Contains("rmdir") || cmd.Contains("remove-item") || cmd.Contains("erase ")) &&
                (cmd.Contains("aegis") || cmd.Contains("ultrondefender") || cmd.Contains("aegisfilter.sys")))
            {
                tamperType = TamperType.BinaryDeletionTamper;
                targetAsset = "AegisPC / UltronDefender Program Dosyaları";
                ruleName = "TAMPER-04: Kritik Antivirüs Dosyalarını Silme Girişimi";
                return true;
            }

            // KURAL 5: Process Hacker, Process Explorer veya PCHunter gibi saldırgan/bellek manipülasyon araçları
            if (img is "processhacker.exe" or "procexp.exe" or "procexp64.exe" or "pchunter.exe" or "pchunter64.exe" or "gmer.exe")
            {
                // Bu araçlar doğrudan başlatıldığında veya Aegis'e yönelik parametrelerle çağrıldığında
                tamperType = TamperType.OffensiveToolTamper;
                targetAsset = "AegisPC Process / Thread Space";
                ruleName = $"TAMPER-05: Bellek Manipülasyon Aracı Tespiti ({img})";
                return true;
            }

            // KURAL 6: taskkill /f /im Aegis* veya Stop-Process
            if ((cmd.Contains("taskkill") || cmd.Contains("stop-process")) &&
                (cmd.Contains("aegis") || cmd.Contains("ultron")))
            {
                tamperType = TamperType.ProcessKillTamper;
                targetAsset = "AegisPC Çalışan Süreçleri";
                ruleName = "TAMPER-06: Taskkill/Stop-Process ile Süreç Sonlandırma Girişimi";
                return true;
            }

            return false;
        }

        private static bool TerminateOffendingProcess(int processId, string imagePath)
        {
            try
            {
                using var proc = Process.GetProcessById(processId);
                proc.Kill(entireProcessTree: true);
                return true;
            }
            catch
            {
                // Fallback: taskkill /f /pid
                try
                {
                    using var killProc = Process.Start(new ProcessStartInfo
                    {
                        FileName = "taskkill.exe",
                        Arguments = $"/F /T /PID {processId}",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                    killProc?.WaitForExit(1500);
                    return killProc?.ExitCode == 0;
                }
                catch { }
            }
            return false;
        }

        private static bool IsLegitimateAegisProcess(int pid, string imagePath)
        {
            try
            {
                int currentPid = Environment.ProcessId;
                if (pid == currentPid) return true;

                string currentExe = Environment.ProcessPath ?? string.Empty;
                if (!string.IsNullOrEmpty(currentExe) && string.Equals(imagePath, currentExe, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                string fileName = Path.GetFileName(imagePath).ToLowerInvariant();
                if (fileName is "aegispc.elevatedhelper.exe" or "aegispc.service.exe")
                {
                    return true;
                }
            }
            catch { }
            return false;
        }

        public void Dispose()
        {
            Stop();
            _eventLogReader.ProcessCreated -= OnProcessCreated;
        }
    }
}
