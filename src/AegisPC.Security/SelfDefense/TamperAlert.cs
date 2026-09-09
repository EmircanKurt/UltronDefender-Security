using System;
using System.Collections.Generic;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Security.SelfDefense
{
    public enum TamperType
    {
        None = 0,
        ServiceConfigTamper = 1,     // sc config Aegis* start= disabled
        RegistryTamper = 2,          // reg add HKLM\SYSTEM\...\Start /d 4
        BinaryDeletionTamper = 3,    // del /f /q AegisPC.exe
        DriverUnloadTamper = 4,      // fltmc unload AegisFilter
        OffensiveToolTamper = 5,     // ProcessHacker, ProcessExplorer
        ProcessKillTamper = 6        // taskkill /f /im Aegis*
    }

    /// <summary>
    /// Anti-Tamper müdahale tespit alarm modeli.
    /// </summary>
    public class TamperAlert
    {
        public Guid AlertId { get; init; } = Guid.NewGuid();
        public int OffendingProcessId { get; init; }
        public string OffendingImagePath { get; init; } = string.Empty;
        public string OffendingCommandLine { get; init; } = string.Empty;
        public string TargetAsset { get; init; } = string.Empty;
        public TamperType TamperType { get; init; } = TamperType.None;
        public string DetectionRule { get; init; } = string.Empty;
        public bool IsContained { get; set; }
        public bool IsSelfHealed { get; set; }
        public string HealingDetails { get; set; } = string.Empty;
        public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;

        public SecurityFinding ToSecurityFinding()
        {
            var reasons = new List<string>
            {
                $"Saldırgan Süreç PID: {OffendingProcessId}",
                $"Saldırgan Görsel: {OffendingImagePath}",
                $"Komut Satırı: {OffendingCommandLine}",
                $"Hedef Korunan Varlık: {TargetAsset}",
                $"Müdahale Türü: {TamperType}",
                $"Kural: {DetectionRule}",
                $"Otomatik İzolasyon (Process Terminated): {(IsContained ? "EVET (Süreç Kapatıldı)" : "HAYIR")}",
                $"Kendini Onarma (Self-Heal): {(IsSelfHealed ? $"EVET ({HealingDetails})" : "GEREKMEDİ")}"
            };

            string title = TamperType switch
            {
                TamperType.ServiceConfigTamper => "🚨 Anti-Tamper: Servis Kapatma/Devre Dışı Bırakma Girişimi Engellendi",
                TamperType.RegistryTamper => "🚨 Anti-Tamper: Kayıt Defteri Start=4 Değiştirme Girişimi Engellendi",
                TamperType.BinaryDeletionTamper => "🚨 Anti-Tamper: Antivirüs Dosyalarını Silme Girişimi Engellendi",
                TamperType.DriverUnloadTamper => "🚨 Anti-Tamper: Çekirdek Minifilter Sürücüsü Boşaltma Girişimi Engellendi",
                TamperType.OffensiveToolTamper => "🚨 Anti-Tamper: Saldırgan Araç (ProcessHacker/PCHunter) Tespiti",
                TamperType.ProcessKillTamper => "🚨 Anti-Tamper: Antivirüs Sürecini Zorla Sonlandırma Girişimi Engellendi",
                _ => "🚨 Anti-Tamper: Güvenlik Motoruna Yetkisiz Müdahale Engellendi"
            };

            return new SecurityFinding
            {
                Id = AlertId,
                ObjectPath = OffendingImagePath,
                ObjectName = System.IO.Path.GetFileName(OffendingImagePath),
                RiskLevel = RiskLevel.ConfirmedMalicious,
                RiskScore = 100,
                Category = FindingCategory.SystemModification,
                Title = title,
                Description = $"AegisPC güvenlik bileşenlerine yönelik yetkisiz müdahale girişimi ({DetectionRule}) tespit edildi ve otomatik izolasyon uygulandı.",
                RiskReasons = reasons,
                ConfidenceLevel = ConfidenceLevel.High,
                Status = FindingStatus.Active,
                FirstObserved = TimestampUtc,
                LastObserved = TimestampUtc,
                CreatedAt = TimestampUtc,
                UpdatedAt = TimestampUtc
            };
        }
    }
}
