using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.PE;
using AegisPC.Contracts.Services;
using AegisPC.Core.Helpers;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;
using PeNet;
using PeNet.Header.Pe;

namespace AegisPC.Security.PE
{
    /// <summary>
    /// Taşınabilir Yürütülebilir (PE) dosyaları dosya kilitlemeden güvenle ayrıştıran,
    /// Rich Header, TLS Callback, Bölüm Anomalileri (W+X) ve Authenticode zincirini inceleyen derin analizci.
    /// </summary>
    public class DeepPeAnalyzer : IDeepPeAnalyzer
    {
        private readonly ILogger<DeepPeAnalyzer>? _logger;

        private static readonly string[] KnownPackerNames = new[]
        {
            "UPX0", "UPX1", "UPX2", ".aspack", ".mpress", ".themida", ".vmp", ".enigma", ".petite", "pecrypt", "pack"
        };

        private readonly ISignatureVerifier _signatureVerifier;

        public DeepPeAnalyzer(ISignatureVerifier? signatureVerifier = null, ILogger<DeepPeAnalyzer>? logger = null)
        {
            _signatureVerifier = signatureVerifier ?? new SignatureVerifier();
            _logger = logger;
        }

        public async Task<PeDeepAnalysisResult> AnalyzeAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return new PeDeepAnalysisResult { FilePath = filePath, IsPeFile = false };
            }

            byte[]? rentedBuffer = null;
            try
            {
                await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 8192, FileOptions.SequentialScan | FileOptions.Asynchronous);
                long readLen = Math.Min(fs.Length, 256 * 1024); // Maks 256 KB analiz sınırı — PE başlıkları ve tabloları için yeterli
                int bytesToRead = (int)readLen;
                
                // ArrayPool: GC baskısını azaltır — her dosya için yeni byte[] alloc edilmez
                rentedBuffer = ArrayPool<byte>.Shared.Rent(bytesToRead);
                int read = await fs.ReadAsync(rentedBuffer.AsMemory(0, bytesToRead), cancellationToken);

                // PeNet, buffer'ın tam boyutunu beklediğinden exact-size kopyası gerekli
                byte[] buffer;
                if (read == bytesToRead && read == rentedBuffer.Length)
                {
                    buffer = rentedBuffer; // Rent edilen buffer tam boyutla eşleşiyorsa kopyalamaya gerek yok
                }
                else
                {
                    buffer = new byte[read];
                    Buffer.BlockCopy(rentedBuffer, 0, buffer, 0, read);
                }

                var result = Analyze(buffer, filePath);
                
                return result;
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error reading PE file '{Path}' for deep analysis.", filePath);
                return new PeDeepAnalysisResult { FilePath = filePath, IsPeFile = false };
            }
            finally
            {
                if (rentedBuffer != null)
                    ArrayPool<byte>.Shared.Return(rentedBuffer);
            }
        }

        public PeDeepAnalysisResult Analyze(byte[] peBytes, string filePath = "")
        {
            var result = new PeDeepAnalysisResult
            {
                FilePath = filePath,
                IsPeFile = false
            };

            if (peBytes == null || peBytes.Length < 64)
            {
                return result;
            }

            // 1. DOS Header 'MZ' (0x5A4D) Doğrulaması
            if (peBytes[0] != 0x4D || peBytes[1] != 0x5A)
            {
                return result;
            }

            // 2. PeNet ile ayrıştırma
            if (!PeFile.TryParse(peBytes, out var peFile) || peFile == null)
            {
                return result;
            }

            result.IsPeFile = true;
            result.IsDll = peFile.IsDll;
            result.IsDriver = peFile.IsDriver;
            result.Is64Bit = peFile.Is64Bit;
            result.ExecutableType = peFile.IsDriver ? "SYS" : (peFile.IsDll ? "DLL" : (peFile.Is64Bit ? "PE64" : "PE32"));

            // 3. Makine ve Alt Sistem
            if (peFile.ImageNtHeaders?.FileHeader != null)
            {
                var machine = (ushort)peFile.ImageNtHeaders.FileHeader.Machine;
                result.Machine = machine switch
                {
                    0x8664 => "AMD64 (x64)",
                    0x014c => "I386 (x86)",
                    0xAA64 => "ARM64",
                    0x01c0 => "ARM",
                    _ => $"0x{machine:X4}"
                };
            }

            if (peFile.ImageNtHeaders?.OptionalHeader != null)
            {
                result.ImageBase = peFile.ImageNtHeaders.OptionalHeader.ImageBase;
                result.AddressOfEntryPoint = peFile.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;
                var sub = peFile.ImageNtHeaders.OptionalHeader.Subsystem;
                result.Subsystem = sub.ToString();
            }

            // 4. Rich Header Ayrıştırma ve Toolchain Hash
            ParseRichHeader(peBytes, peFile, result);

            // 5. TLS (Thread Local Storage) Callbacks
            ParseTlsCallbacks(peFile, result);

            // 6. PE Bölüm Analizi, Entropi ve W+X Anomalileri
            ParseSections(peBytes, peFile, result);

            // 7. İçe Aktarılan API'lar (Imports)
            ParseImports(peFile, result);

            // 8. Authenticode Sertifika Zinciri Analizi
            ParseAuthenticode(filePath, peFile, result);

            return result;
        }

        private void ParseRichHeader(byte[] peBytes, PeFile peFile, PeDeepAnalysisResult result)
        {
            try
            {
                // Rich Header 'DanS' ve 'Rich' etiketlerini arar
                int richOffset = -1;
                for (int i = 0x80; i < Math.Min(peBytes.Length - 8, 0x1000); i += 4)
                {
                    if (peBytes[i] == 'R' && peBytes[i + 1] == 'i' && peBytes[i + 2] == 'c' && peBytes[i + 3] == 'h')
                    {
                        richOffset = i;
                        break;
                    }
                }

                if (richOffset != -1 && richOffset + 8 <= peBytes.Length)
                {
                    uint xorKey = BitConverter.ToUInt32(peBytes, richOffset + 4);
                    result.HasRichHeader = true;

                    // DanS başlangıcını ara
                    int dansOffset = -1;
                    for (int i = richOffset - 8; i >= 0x40; i -= 4)
                    {
                        uint val = BitConverter.ToUInt32(peBytes, i) ^ xorKey;
                        if (val == 0x536E6144) // 'DanS' in Little-Endian
                        {
                            dansOffset = i;
                            break;
                        }
                    }

                    if (dansOffset != -1)
                    {
                        // DanS'ten Rich'e kadar olan verinin hash'ini al
                        int richBlockLen = (richOffset + 8) - dansOffset;
                        byte[] richBlock = new byte[richBlockLen];
                        Array.Copy(peBytes, dansOffset, richBlock, 0, richBlockLen);

                        using var md5 = MD5.Create();
                        result.RichHeaderHashMd5 = Convert.ToHexString(md5.ComputeHash(richBlock)).ToLowerInvariant();

                        using var sha256 = SHA256.Create();
                        result.RichHeaderHashSha256 = Convert.ToHexString(sha256.ComputeHash(richBlock)).ToLowerInvariant();

                        // Girişleri çöz (DanS sonrasındaki 3 adet 32-bit sıfır padding'ten sonra başlar)
                        int entryStart = dansOffset + 16;
                        for (int i = entryStart; i < richOffset; i += 8)
                        {
                            if (i + 8 > richOffset) break;
                            uint compProd = BitConverter.ToUInt32(peBytes, i) ^ xorKey;
                            uint count = BitConverter.ToUInt32(peBytes, i + 4) ^ xorKey;

                            ushort prodId = (ushort)(compProd >> 16);
                            ushort buildNum = (ushort)(compProd & 0xFFFF);

                            result.RichEntries.Add(new PeRichHeaderEntry
                            {
                                ProductId = prodId,
                                BuildNumber = buildNum,
                                CompilerId = prodId,
                                Count = count,
                                Description = GetCompilerDescription(prodId, buildNum)
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Rich Header parsing failed.");
            }
        }

        private static string GetCompilerDescription(ushort prodId, ushort buildNum)
        {
            return prodId switch
            {
                0x0001 => $"Import0 (Build {buildNum})",
                0x0093 => $"Visual C++ 6.0 SP5 (Build {buildNum})",
                0x00AA => $"Visual C++ 2003 .NET (Build {buildNum})",
                0x00D3 => $"Visual C++ 2005 (Build {buildNum})",
                0x00FF => $"Visual C++ 2008 (Build {buildNum})",
                0x0104 => $"Visual C++ 2010 (Build {buildNum})",
                0x012F => $"Visual C++ 2012 (Build {buildNum})",
                0x014B => $"Visual C++ 2013 (Build {buildNum})",
                0x015E => $"Visual C++ 2015 (Build {buildNum})",
                0x0167 => $"Visual C++ 2017 (Build {buildNum})",
                0x0178 => $"Visual C++ 2019 (Build {buildNum})",
                0x0190 => $"Visual C++ 2022 (Build {buildNum})",
                _ => $"MSVC Toolchain ID 0x{prodId:X4} (Build {buildNum})"
            };
        }

        private void ParseTlsCallbacks(PeFile peFile, PeDeepAnalysisResult result)
        {
            try
            {
                var dataDirs = peFile.ImageNtHeaders?.OptionalHeader?.DataDirectory;
                if (dataDirs != null && dataDirs.Length > 9)
                {
                    var tlsDir = dataDirs[9]; // IMAGE_DIRECTORY_ENTRY_TLS (Index 9)
                    if (tlsDir.VirtualAddress > 0 && tlsDir.Size > 0)
                    {
                        result.HasTlsCallbacks = true;
                        result.TlsCallbackCount = 1;
                        result.Anomalies.Add("PE dosyasında TLS Directory tespit edildi (Erken kod çalıştırma / Anti-debug).");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "TLS callbacks parsing failed.");
            }
        }

        private void ParseSections(byte[] peBytes, PeFile peFile, PeDeepAnalysisResult result)
        {
            try
            {
                if (peFile.ImageSectionHeaders == null) return;

                foreach (var section in peFile.ImageSectionHeaders)
                {
                    var name = section.Name?.Trim('\0') ?? string.Empty;
                    uint chars = (uint)section.Characteristics;
                    bool isExec = (chars & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE
                    bool isWrite = (chars & 0x80000000) != 0; // IMAGE_SCN_MEM_WRITE
                    bool isRead = (chars & 0x40000000) != 0; // IMAGE_SCN_MEM_READ

                    // Bölümün verisinden Shannon entropisi hesapla
                    double entropy = 0.0;
                    uint rawPtr = section.PointerToRawData;
                    uint rawSize = section.SizeOfRawData;

                    if (rawPtr < peBytes.Length && rawSize > 0)
                    {
                        long bytesToRead = Math.Min(rawSize, peBytes.Length - rawPtr);
                        if (bytesToRead > 0)
                        {
                            byte[] secBytes = new byte[bytesToRead];
                            Array.Copy(peBytes, rawPtr, secBytes, 0, bytesToRead);
                            entropy = EntropyCalculator.CalculateEntropy(secBytes);
                        }
                    }

                    bool isPacker = KnownPackerNames.Any(p => name.Contains(p, StringComparison.OrdinalIgnoreCase));
                    if (isPacker)
                    {
                        result.PackerIndicators.Add($"Şüpheli/Paketlenmiş bölüm adı: '{name}'");
                    }

                    var detail = new PeSectionDetail
                    {
                        Name = name,
                        VirtualAddress = section.VirtualAddress,
                        VirtualSize = section.VirtualSize,
                        RawAddress = rawPtr,
                        RawSize = rawSize,
                        Characteristics = chars,
                        Entropy = entropy,
                        IsExecutable = isExec,
                        IsWritable = isWrite,
                        IsReadable = isRead,
                        IsKnownPackerName = isPacker
                    };

                    result.Sections.Add(detail);

                    // W+X Anomali Tespiti
                    if (detail.IsWritableAndExecutable)
                    {
                        result.Anomalies.Add($"W+X Anomalisi: '{name}' bölümü hem yazılabilir hem çalıştırılabilir.");
                    }

                    // Yüksek Entropi Tespiti
                    if (entropy >= 7.2 && rawSize > 1024)
                    {
                        result.Anomalies.Add($"Yüksek Entropi: '{name}' bölümü ({entropy:F2}/8.0) şifrelenmiş veya sıkıştırılmış.");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Section analysis failed.");
            }
        }

        private void ParseImports(PeFile peFile, PeDeepAnalysisResult result)
        {
            try
            {
                if (peFile.ImportedFunctions != null)
                {
                    result.NumberOfImports = peFile.ImportedFunctions.Length;
                    var dlls = peFile.ImportedFunctions
                        .Select(f => f.DLL)
                        .Where(d => !string.IsNullOrEmpty(d))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();
                    result.ImportedDlls.AddRange(dlls!);

                    var suspiciousApis = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    {
                        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
                        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "QueueUserAPC"
                    };

                    foreach (var imp in peFile.ImportedFunctions)
                    {
                        if (!string.IsNullOrEmpty(imp.Name) && suspiciousApis.Contains(imp.Name))
                        {
                            result.SuspiciousImportedApis.Add($"{imp.DLL}!{imp.Name}");
                        }
                    }
                }

                if (peFile.ExportedFunctions != null)
                {
                    result.NumberOfExports = peFile.ExportedFunctions.Length;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Imports/Exports parsing failed.");
            }
        }

        private void ParseAuthenticode(string filePath, PeFile peFile, PeDeepAnalysisResult result)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return;

            try
            {
                var sigInfo = _signatureVerifier.VerifySignatureAsync(filePath).GetAwaiter().GetResult();
                if (sigInfo != null && sigInfo.IsSigned)
                {
                    result.Certificate.IsSigned = true;
                    result.Certificate.IsValid = sigInfo.IsValid;
                    result.Certificate.Subject = sigInfo.Publisher ?? string.Empty;
                    result.Certificate.Issuer = sigInfo.Issuer ?? string.Empty;
                    result.Certificate.Thumbprint = sigInfo.Thumbprint ?? string.Empty;
                    result.Certificate.SerialNumber = sigInfo.SerialNumber ?? string.Empty;
                    result.Certificate.ValidFrom = sigInfo.ValidFrom;
                    result.Certificate.ValidTo = sigInfo.ValidTo;
                    result.Certificate.SignatureAlgorithm = sigInfo.SignatureAlgorithm ?? string.Empty;

                    if (result.Certificate.Subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                        result.Certificate.Issuer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Certificate.IsMicrosoftTrusted = result.Certificate.IsValid;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Authenticode chain verification error on {Path}", filePath);
            }
        }

        #region WinVerifyTrust P/Invoke
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

        private static bool CheckWinVerifyTrust(string filePath)
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            IntPtr pWVTData = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA)));

            try
            {
                Marshal.StructureToPtr(fileInfo, pFileInfo, false);

                var wvtData = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = 2, // WTD_UI_NONE
                    fdwRevocationChecks = 0, // WTD_REVOKE_NONE
                    dwUnionChoice = 1, // WTD_CHOICE_FILE
                    pFile = pFileInfo,
                    dwStateAction = 0, // WTD_STATEACTION_IGNORE
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = null,
                    dwProvFlags = 0x00000040 | 0x00000080, // WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };

                Marshal.StructureToPtr(wvtData, pWVTData, false);

                int winTrustResult = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pWVTData);
                return winTrustResult == 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(pFileInfo);
                Marshal.FreeHGlobal(pWVTData);
            }
        }
        #endregion
    }
}
