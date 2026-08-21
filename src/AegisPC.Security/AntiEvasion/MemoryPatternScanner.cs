using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.AntiEvasion;
using AegisPC.Contracts.Detection;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.AntiEvasion
{
    /// <summary>
    /// Gelişmiş Süreç Bellek Analizörü (PE-sieve & SystemInformer Mimarisi).
    /// Process Hollowing, Inline Hooking, Unbacked RWX Sayfaları ve Kabuk Kodu (Shellcode) Tespiti yapar.
    /// </summary>
    public class MemoryPatternScanner : IMemoryPatternScanner
    {
        private readonly ILogger<MemoryPatternScanner>? _logger;

        #region Windows Native API P/Invoke

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            QueryInformation = 0x0400,
            VirtualMemoryRead = 0x0010,
            QueryLimitedInformation = 0x1000
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public ushort PartitionId;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_PRIVATE = 0x20000;
        private const uint MEM_IMAGE = 0x1000000;

        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const uint PAGE_GUARD = 0x100;
        private const uint PAGE_NOACCESS = 0x01;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        #endregion

        // Bilinen Kabuk Kodu ve Bellek İçi Tehdit İmzaları
        private static readonly (string ThreatName, string Category, int Score, byte[] Signature, string Description)[] KnownMemoryPatterns = new[]
        {
            // Cobalt Strike Beacon x64 Reflective Loader
            ("CobaltStrike.Beacon.ReflectiveLoader", "Beacon", 100, new byte[] { 0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC }, "Cobalt Strike Beacon yansımalı DLL yükleyici bellek başlığı"),
            
            // Meterpreter Reverse TCP Shellcode x64 (FC 48 83 E4 F0 E8 C0 00 00 00)
            ("Metasploit.Meterpreter.Stager.x64", "Shellcode", 95, new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00 }, "Metasploit Meterpreter x64 reverse TCP stager kabuk kodu"),

            // Meterpreter Reverse TCP Shellcode x86 (FC E8 82 00 00 00 60 89 E5)
            ("Metasploit.Meterpreter.Stager.x86", "Shellcode", 95, new byte[] { 0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xE5 }, "Metasploit Meterpreter x86 reverse TCP stager kabuk kodu"),

            // AMSI Patch (B8 57 00 07 80 C3 - mov eax, 0x80070057; ret)
            ("AMSI.MemoryPatch.InvalidArg", "DefenseEvasion", 90, new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }, "Bellek içi AmsiScanBuffer fonksiyonu E_INVALIDARG yaması"),

            // AMSI Patch (31 C0 C3 - xor eax, eax; ret)
            ("AMSI.MemoryPatch.ZeroReturn", "DefenseEvasion", 90, new byte[] { 0x31, 0xC0, 0xC3 }, "Bellek içi AmsiScanBuffer fonksiyonu S_OK sıfırlama yaması"),

            // NOP Sled Shellcode Pattern (90 90 90 90 90 90 90 90)
            ("Generic.Shellcode.NopSled", "Shellcode", 85, new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }, "Yüksek uzunlukta NOP kızağı (Shellcode Execution Sled)")
        };

        public MemoryPatternScanner(ILogger<MemoryPatternScanner>? logger = null)
        {
            _logger = logger;
        }

        public MemoryScanVerdict ScanBuffer(byte[] memoryBytes)
        {
            var verdict = new MemoryScanVerdict
            {
                MemorySize = memoryBytes?.Length ?? 0
            };

            if (memoryBytes == null || memoryBytes.Length == 0) return verdict;

            foreach (var (threatName, category, score, pattern, desc) in KnownMemoryPatterns)
            {
                int index = IndexOfPattern(memoryBytes, pattern);
                if (index >= 0)
                {
                    verdict.IsMaliciousMemoryFound = true;
                    verdict.Confidence = 0.98;
                    verdict.SeverityScore = score;
                    verdict.ThreatTitle = $"🚨 Bellek İçi Tehdit: {threatName}";
                    verdict.ThreatCategory = category;
                    verdict.MatchedPattern = threatName;
                    verdict.MemoryAddress = (ulong)index;
                    verdict.Evidences.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.BehaviorMemory,
                        RuleName = $"MEMORY_{threatName.ToUpperInvariant().Replace(".", "_")}",
                        ScoreContribution = score,
                        Confidence = EvidenceConfidence.Absolute,
                        Description = desc
                    });
                    break;
                }
            }

            return verdict;
        }

        public async Task<MemoryScanVerdict> ScanProcessMemoryAsync(int pid, CancellationToken cancellationToken = default)
        {
            var verdict = new MemoryScanVerdict();
            if (pid <= 4) return verdict;

            await Task.Run(() =>
            {
                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    hProcess = OpenProcess(ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VirtualMemoryRead, false, pid);
                    if (hProcess == IntPtr.Zero)
                    {
                        // Try with QueryLimitedInformation fallback
                        hProcess = OpenProcess(ProcessAccessFlags.QueryLimitedInformation | ProcessAccessFlags.VirtualMemoryRead, false, pid);
                    }

                    if (hProcess == IntPtr.Zero) return;

                    IntPtr currentAddress = IntPtr.Zero;
                    long maxAddress = Environment.Is64BitProcess ? 0x7FFFFFFFFFF : 0x7FFFFFFF;

                    while ((long)currentAddress < maxAddress && !cancellationToken.IsCancellationRequested)
                    {
                        int result = VirtualQueryEx(hProcess, currentAddress, out MEMORY_BASIC_INFORMATION mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
                        if (result == 0) break;

                        // Yürütülebilir bellek sayfalarını incele (PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE)
                        bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                        bool isGuarded = (mbi.Protect & PAGE_GUARD) != 0 || (mbi.Protect & PAGE_NOACCESS) != 0;

                        if (mbi.State == MEM_COMMIT && isExecutable && !isGuarded)
                        {
                            // 1. Unbacked Executable Memory (RWX + MEM_PRIVATE)
                            // Diskte herhangi bir DLL veya dosya eşlemesi olmayan dinamik yürütülebilir bellek alanı
                            if (mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0)
                            {
                                int regionSize = (int)Math.Min((long)mbi.RegionSize, 1024 * 1024); // Max 1MB read
                                if (regionSize > 0)
                                {
                                    byte[] buffer = new byte[regionSize];
                                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, regionSize, out IntPtr bytesRead) && (int)bytesRead > 0)
                                    {
                                        var bufferVerdict = ScanBuffer(buffer);
                                        if (bufferVerdict.IsMaliciousMemoryFound)
                                        {
                                            verdict.IsMaliciousMemoryFound = true;
                                            verdict.SeverityScore = Math.Max(verdict.SeverityScore, bufferVerdict.SeverityScore);
                                            verdict.ThreatTitle = bufferVerdict.ThreatTitle;
                                            verdict.ThreatCategory = bufferVerdict.ThreatCategory;
                                            verdict.MemoryAddress = (ulong)(long)mbi.BaseAddress;
                                            verdict.Evidences.AddRange(bufferVerdict.Evidences);
                                            break;
                                        }

                                        // Şüpheli Unbacked RWX Sayfası Kanıtı Ekle
                                        verdict.Evidences.Add(new SecurityEvidence
                                        {
                                            Category = EvidenceCategory.BehaviorMemory,
                                            RuleName = "MEMORY_UNBACKED_RWX_PAGE",
                                            ScoreContribution = 75,
                                            Confidence = EvidenceConfidence.High,
                                            Description = $"Diskte dosyası bulunmayan şüpheli yürütülebilir/yazılabilir bellek sayfası (RWX Private, Boyut: {bytesRead} bayt)"
                                        });

                                        verdict.SeverityScore = Math.Max(verdict.SeverityScore, 75);
                                        verdict.ThreatTitle = "⚠️ Şüpheli Bellek İçi Kod Enjeksiyonu (Unbacked RWX)";
                                        verdict.ThreatCategory = "ProcessInjection";
                                        verdict.IsMaliciousMemoryFound = true;
                                    }
                                }
                            }
                        }

                        // Bir sonraki bellek bölgesine ilerle
                        long nextAddr = (long)mbi.BaseAddress + (long)mbi.RegionSize;
                        if (nextAddr <= (long)currentAddress) break;
                        currentAddress = (IntPtr)nextAddr;
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogTrace(ex, "Memory scan error for PID {Pid}", pid);
                }
                finally
                {
                    if (hProcess != IntPtr.Zero)
                    {
                        CloseHandle(hProcess);
                    }
                }
            }, cancellationToken);

            return verdict;
        }

        /// <summary>
        /// Hedef süreçte diskteki orijinal DLL ile bellekteki kod bölümünü karşılaştırarak Inline API Hooking tespiti yapar.
        /// </summary>
        public MemoryScanVerdict DetectInlineHooks(int pid, string dllPath = @"C:\Windows\System32\ntdll.dll")
        {
            var verdict = new MemoryScanVerdict();
            if (pid <= 4 || !File.Exists(dllPath)) return verdict;

            try
            {
                byte[] diskBytes = File.ReadAllBytes(dllPath);
                using var proc = Process.GetProcessById(pid);

                // Süreçte yüklü modülü bul
                ProcessModule? targetModule = null;
                foreach (ProcessModule mod in proc.Modules)
                {
                    if (string.Equals(mod.ModuleName, Path.GetFileName(dllPath), StringComparison.OrdinalIgnoreCase))
                    {
                        targetModule = mod;
                        break;
                    }
                }

                if (targetModule == null) return verdict;

                IntPtr hProcess = OpenProcess(ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VirtualMemoryRead, false, pid);
                if (hProcess == IntPtr.Zero) return verdict;

                try
                {
                    // Modülün ilk 4096 baytını (PE Header + Entry) oku ve karşılaştır
                    int checkSize = Math.Min(diskBytes.Length, 4096);
                    byte[] memBytes = new byte[checkSize];

                    if (ReadProcessMemory(hProcess, targetModule.BaseAddress, memBytes, checkSize, out IntPtr read) && (int)read == checkSize)
                    {
                        // Check for JMP / Detour hooks at critical entry points
                        // 0xE9 (JMP rel32), 0xFF 0x25 (JMP qword ptr), 0x48 0xB8 (mov rax, imm64)
                        for (int i = 0x400; i < checkSize - 5; i++)
                        {
                            if (diskBytes[i] != memBytes[i])
                            {
                                if (memBytes[i] == 0xE9 || (memBytes[i] == 0xFF && memBytes[i + 1] == 0x25) || (memBytes[i] == 0x48 && memBytes[i + 1] == 0xB8))
                                {
                                    verdict.IsMaliciousMemoryFound = true;
                                    verdict.SeverityScore = 90;
                                    verdict.ThreatTitle = $"🚨 Tespit Edildi: Inline API Hook / EDR Unhooking ({Path.GetFileName(dllPath)})";
                                    verdict.ThreatCategory = "DefenseEvasion";
                                    verdict.MemoryAddress = (ulong)((long)targetModule.BaseAddress + i);
                                    verdict.Evidences.Add(new SecurityEvidence
                                    {
                                        Category = EvidenceCategory.BehaviorMemory,
                                        RuleName = "MEMORY_INLINE_API_HOOK",
                                        ScoreContribution = 90,
                                        Confidence = EvidenceConfidence.High,
                                        Description = $"{Path.GetFileName(dllPath)} modülünde bellek içi bayt yönlendirmesi (JMP/CALL Hook) tespit edildi. Orijinal: 0x{diskBytes[i]:X2}, Bellek: 0x{memBytes[i]:X2}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Inline hook detection exception for PID {Pid}", pid);
            }

            return verdict;
        }

        /// <summary>
        /// Process Hollowing Tespiti: Bellekteki PE başlığı ile diskteki orijinal dosya başlığı uyuşmazlığını denetler.
        /// </summary>
        public MemoryScanVerdict DetectProcessHollowing(int pid, string diskExecutablePath)
        {
            var verdict = new MemoryScanVerdict();
            if (pid <= 4 || !File.Exists(diskExecutablePath)) return verdict;

            try
            {
                using var proc = Process.GetProcessById(pid);
                var mainMod = proc.MainModule;
                if (mainMod == null) return verdict;

                byte[] diskBytes = File.ReadAllBytes(diskExecutablePath);
                if (diskBytes.Length < 0x200) return verdict;

                IntPtr hProcess = OpenProcess(ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VirtualMemoryRead, false, pid);
                if (hProcess == IntPtr.Zero) return verdict;

                try
                {
                    byte[] memHeader = new byte[0x400]; // 1KB header
                    if (ReadProcessMemory(hProcess, mainMod.BaseAddress, memHeader, 0x400, out IntPtr read) && (int)read >= 0x200)
                    {
                        // MZ header and PE signature check
                        bool diskIsMz = diskBytes[0] == 'M' && diskBytes[1] == 'Z';
                        bool memIsMz = memHeader[0] == 'M' && memHeader[1] == 'Z';

                        if (diskIsMz && memIsMz)
                        {
                            int diskPeOffset = BitConverter.ToInt32(diskBytes, 0x3C);
                            int memPeOffset = BitConverter.ToInt32(memHeader, 0x3C);

                            if (diskPeOffset > 0 && memPeOffset > 0 && diskPeOffset < diskBytes.Length - 0x30 && memPeOffset < 0x3D0)
                            {
                                // Compare EntryPoint RVA (AddressOfEntryPoint is at PE + 0x28)
                                uint diskEntryPoint = BitConverter.ToUInt32(diskBytes, diskPeOffset + 0x28);
                                uint memEntryPoint = BitConverter.ToUInt32(memHeader, memPeOffset + 0x28);

                                if (diskEntryPoint != memEntryPoint && diskEntryPoint != 0 && memEntryPoint != 0)
                                {
                                    verdict.IsMaliciousMemoryFound = true;
                                    verdict.SeverityScore = 95;
                                    verdict.ThreatTitle = "🚨 Tespit Edildi: Process Hollowing (PE Başlık Anomalisi)";
                                    verdict.ThreatCategory = "ProcessInjection";
                                    verdict.MemoryAddress = (ulong)(long)mainMod.BaseAddress;
                                    verdict.Evidences.Add(new SecurityEvidence
                                    {
                                        Category = EvidenceCategory.BehaviorMemory,
                                        RuleName = "MEMORY_PROCESS_HOLLOWING",
                                        ScoreContribution = 95,
                                        Confidence = EvidenceConfidence.Absolute,
                                        Description = $"Süreç giriş noktası (AddressOfEntryPoint) disk ve bellek arasında uyuşmuyor! Disk: 0x{diskEntryPoint:X8}, Bellek: 0x{memEntryPoint:X8}"
                                    });
                                }
                            }
                        }
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Process Hollowing scan exception for PID {Pid}", pid);
            }

            return verdict;
        }

        private static int IndexOfPattern(byte[] source, byte[] pattern)
        {
            if (source == null || pattern == null || source.Length < pattern.Length) return -1;

            for (int i = 0; i <= source.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (source[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }

            return -1;
        }
    }
}
