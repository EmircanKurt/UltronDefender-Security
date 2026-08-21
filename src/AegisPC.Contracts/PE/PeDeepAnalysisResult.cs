using System;
using System.Collections.Generic;
using System.Linq;

namespace AegisPC.Contracts.PE
{
    /// <summary>
    /// Taşınabilir Yürütülebilir (PE) Dosya Derin Başlık ve Güvenlik Analiz Sonucu.
    /// </summary>
    public class PeDeepAnalysisResult
    {
        public bool IsPeFile { get; set; }
        public string FilePath { get; set; } = string.Empty;
        public string ExecutableType { get; set; } = "UNKNOWN"; // "PE32", "PE64", "DLL", "SYS"
        public string Machine { get; set; } = "UNKNOWN"; // "AMD64", "I386", "ARM64"
        public string Subsystem { get; set; } = "UNKNOWN"; // "WindowsGUI", "WindowsCUI", "Native"
        public ulong ImageBase { get; set; }
        public uint AddressOfEntryPoint { get; set; }
        public bool Is64Bit { get; set; }
        public bool IsDll { get; set; }
        public bool IsDriver { get; set; }

        // --- Rich Header Telemetrisi ---
        public bool HasRichHeader { get; set; }
        public string RichHeaderHashMd5 { get; set; } = string.Empty;
        public string RichHeaderHashSha256 { get; set; } = string.Empty;
        public List<PeRichHeaderEntry> RichEntries { get; set; } = new();

        // --- TLS (Thread Local Storage) Callback Telemetrisi ---
        public bool HasTlsCallbacks { get; set; }
        public int TlsCallbackCount { get; set; }
        public List<ulong> TlsCallbackAddresses { get; set; } = new();

        // --- PE Bölüm Anomalileri ---
        public List<PeSectionDetail> Sections { get; set; } = new();
        public bool HasWritableExecutableSection => Sections.Any(s => s.IsWritableAndExecutable);
        public bool HasHighEntropySections => Sections.Any(s => s.Entropy >= 7.2);
        public double MaxSectionEntropy => Sections.Count > 0 ? Sections.Max(s => s.Entropy) : 0.0;
        public List<string> PackerIndicators { get; set; } = new();
        public List<string> Anomalies { get; set; } = new();

        // --- İçe/Dışa Aktarımlar (Imports / Exports) ---
        public int NumberOfImports { get; set; }
        public int NumberOfExports { get; set; }
        public List<string> ImportedDlls { get; set; } = new();
        public List<string> SuspiciousImportedApis { get; set; } = new();

        // --- Authenticode Sertifikası ---
        public PeCertificateDetail Certificate { get; set; } = new();

        public override string ToString() => $"PE Deep Analysis: {ExecutableType}, Sections: {Sections.Count}, W+X: {HasWritableExecutableSection}, TLS: {HasTlsCallbacks}, Rich: {HasRichHeader}, CertValid: {Certificate.IsValid}";
    }
}
