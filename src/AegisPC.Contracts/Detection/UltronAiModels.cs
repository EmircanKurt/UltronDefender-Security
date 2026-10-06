using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Detection
{
    /// <summary>
    /// Ultron AI tarafından bir dosyadan veya bellek bloğundan çıkarılan 20+ boyutlu sayısal özellik vektörü.
    /// </summary>
    public class UltronFeatureVector
    {
        /// <summary>Reports configured feature extraction coverage, not a malware verdict.</summary>
        public ContentClassificationCoverage Coverage { get; set; } = ContentClassificationCoverage.Unknown;
        /// <summary>Records unreadable, malformed or budget-limited feature input.</summary>
        public List<string> CoverageLimitations { get; set; } = new();
        /// <summary>Identifies the bounded, deterministic feature schema.</summary>
        public string FeatureVersion { get; set; } = "static-pe-v2";
        /// <summary>Identifies bytes hashed while the caller holds the same source open.</summary>
        public string SHA256 { get; set; } = string.Empty;
        public string TargetPath { get; set; } = string.Empty;
        public long FileSizeBytes { get; set; }

        // Entropi Göstergeleri
        public float EntropyOverall { get; set; }
        public float EntropyMaxSection { get; set; }
        public float EntropyCodeSection { get; set; }

        // PE Yapısal Göstergeleri
        public int SectionCount { get; set; }
        public bool HasSuspiciousSectionName { get; set; }
        public string PrimaryPackerName { get; set; } = string.Empty;
        public bool HasWritableExecutableSection { get; set; } // W^X kuralı ihlali
        public float SizeRawVsVirtualRatio { get; set; }
        public bool HasTlsCallbacks { get; set; }
        public int Subsystem { get; set; }

        // API İçe Aktarım Göstergeleri
        public int TotalImportsCount { get; set; }
        public int SuspiciousApiCount { get; set; }
        public float DangerousApiRatio { get; set; }
        public bool HasMemoryAllocationApis { get; set; }
        public bool HasProcessInjectionApis { get; set; }
        public bool HasAntiDebuggingApis { get; set; }

        // Güven ve İmza Göstergeleri
        public bool IsSigned { get; set; }
        public bool IsSignatureValid { get; set; }
        public bool IsCommercialPublisher { get; set; }

        // Konum ve Bağlam
        public bool IsUserWritableLocation { get; set; } // Temp, Downloads, AppData
        public bool IsSystemLocation { get; set; }       // System32, SysWOW64
    }

    /// <summary>
    /// Ultron AI bilişsel ve istatistiksel analiz sonucu.
    /// </summary>
    public class UltronAiVerdict
    {
        public DetectionVerdict Verdict { get; set; } = DetectionVerdict.Unknown;
        /// <summary>Always null: handcrafted weights are not a calibrated malware probability.</summary>
        public float? MalwareProbability { get; set; }
        /// <summary>Reports feature extraction scope independently of the review priority.</summary>
        public ContentClassificationCoverage Coverage { get; set; } = ContentClassificationCoverage.Unknown;
        /// <summary>Records limitations that prevent a complete static review.</summary>
        public List<string> CoverageLimitations { get; set; } = new();
        public int CalculatedRiskScore { get; set; }   // 0 - 100
        public string PrimaryDiagnosis { get; set; } = string.Empty;
        public string ReasoningDeduction { get; set; } = string.Empty;
        public List<string> TriggeredAnomalies { get; set; } = new();
        public List<string> MitreTactics { get; set; } = new();
        public double InferenceTimeMs { get; set; }
        public bool RequiresImmediateBlock { get; set; }
    }

    /// <summary>
    /// Ultron AI bağımsız sezgisel analiz ve tehdit avı arayüzü.
    /// </summary>
    public interface IUltronAiEngine
    {
        /// <summary>
        /// Belirtilen dosyayı anatomik özellik vektörüne dönüştürür ve Ultron AI bilişsel değerlendirmesi yapar.
        /// </summary>
        Task<UltronAiVerdict> EvaluateFileAsync(string filePath, CancellationToken cancellationToken = default);

        /// <summary>Inspects the caller-owned locked source; legacy implementations cannot assert identical-byte inspection.</summary>
        Task<UltronAiVerdict> EvaluateLockedFileAsync(Stream source, string filePath,
            FileContentClassification classification, CancellationToken cancellationToken = default)
            => Task.FromResult(new UltronAiVerdict { PrimaryDiagnosis = "LockedContentInspectionUnavailable" });

        /// <summary>
        /// Verilen özellik vektörü üzerinden doğrudan çıkarım yapar.
        /// </summary>
        UltronAiVerdict EvaluateVector(UltronFeatureVector vector);
    }
}
