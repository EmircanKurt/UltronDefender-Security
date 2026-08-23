using System;
using System.Buffers;
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

        private const int MaxPeReadBytes = 128 * 1024; // 128 KB sınır — PE başlıkları ve tabloları için fazlasıyla yeterli (LOH baskısını sıfırlar)

        /// <summary>
        /// Bellek korumalı PE analizi — dosyayı 128 KB ile sınırlandırır,
        /// MZ başlığını doğrular ve ArrayPool kullanarak GC/LOH baskısını sıfırlar.
        /// </summary>
        public static PeAnalysisResult Analyze(string filePath)
        {
            var result = new PeAnalysisResult();
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return result;

            byte[]? rentedBuffer = null;
            try
            {
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length < 64) return result;

                int bytesToRead = (int)Math.Min(fileInfo.Length, MaxPeReadBytes);
                rentedBuffer = ArrayPool<byte>.Shared.Rent(bytesToRead);

                int read;
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, bufferSize: 8192,
                    FileOptions.SequentialScan))
                {
                    read = fs.Read(rentedBuffer, 0, bytesToRead);
                }

                if (read < 64 || rentedBuffer[0] != 0x4D || rentedBuffer[1] != 0x5A) // 'MZ' kontrolü
                {
                    result.IsPeFile = false;
                    return result;
                }

                byte[] exactBuffer;
                if (read == rentedBuffer.Length)
                {
                    exactBuffer = rentedBuffer;
                }
                else
                {
                    exactBuffer = new byte[read];
                    Buffer.BlockCopy(rentedBuffer, 0, exactBuffer, 0, read);
                }

                if (!PeFile.TryParse(exactBuffer, out var peFile) || peFile == null)
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
            finally
            {
                if (rentedBuffer != null)
                {
                    ArrayPool<byte>.Shared.Return(rentedBuffer);
                }
            }

            return result;
        }
    }
}
