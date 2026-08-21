using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using PeNet;

namespace AegisPC.Security.Scanning
{
    public class PeAnalysisResult
    {
        public bool IsPeFile { get; set; }
        public string ExecutableType { get; set; } = "Other";
        public bool IsPacked { get; set; }
        public List<string> PackerIndicators { get; set; } = new();
        public List<string> SuspiciousImports { get; set; } = new();
        public bool HasWritableExecutableSection { get; set; }
    }

    public static class PeAnalyzer
    {
        private static readonly HashSet<string> SuspiciousApiNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "QueueUserAPC", "SetWindowsHookExA", "SetWindowsHookExW",
            "URLDownloadToFileA", "URLDownloadToFileW",
            "NtUnmapViewOfSection", "ZwUnmapViewOfSection"
        };

        private static readonly string[] KnownPackerSections = new[]
        {
            "UPX0", "UPX1", "UPX2", ".aspack", ".mpress", ".themida", ".vmp"
        };

        public static PeAnalysisResult Analyze(string filePath)
        {
            var result = new PeAnalysisResult();
            if (!File.Exists(filePath)) return result;

            try
            {
                byte[] peBytes;
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096))
                {
                    long len = Math.Min(fs.Length, 20 * 1024 * 1024);
                    peBytes = new byte[len];
                    fs.Read(peBytes, 0, (int)len);
                }

                if (!PeFile.TryParse(peBytes, out var peFile) || peFile == null)
                {
                    result.IsPeFile = false;
                    return result;
                }

                result.IsPeFile = true;
                result.ExecutableType = peFile.IsDll ? "DLL" : (peFile.Is64Bit ? "PE64" : "PE32");

                // Check sections
                if (peFile.ImageSectionHeaders != null)
                {
                    foreach (var section in peFile.ImageSectionHeaders)
                    {
                        var name = section.Name?.Trim('\0') ?? string.Empty;
                        if (KnownPackerSections.Any(p => name.Contains(p, StringComparison.OrdinalIgnoreCase)))
                        {
                            result.IsPacked = true;
                            result.PackerIndicators.Add($"Şüpheli/Paketlenmiş bölüm adı: '{name}'");
                        }

                        // Bitwise check: 0x20000000 = MEM_EXECUTE, 0x80000000 = MEM_WRITE
                        uint characteristics = (uint)section.Characteristics;
                        bool isExecute = (characteristics & 0x20000000) != 0;
                        bool isWrite = (characteristics & 0x80000000) != 0;
                        if (isExecute && isWrite)
                        {
                            result.HasWritableExecutableSection = true;
                            result.PackerIndicators.Add($"Hem yazılabilir hem çalıştırılabilir bölüm: '{name}' (W+X anomalisi)");
                        }
                    }
                }

                // Check imported functions
                if (peFile.ImportedFunctions != null)
                {
                    foreach (var imp in peFile.ImportedFunctions)
                    {
                        if (!string.IsNullOrEmpty(imp.Name) && SuspiciousApiNames.Contains(imp.Name))
                        {
                            result.SuspiciousImports.Add(imp.Name);
                        }
                    }
                }
            }
            catch
            {
                // Fallback for corrupt PE headers
            }

            return result;
        }
    }
}
