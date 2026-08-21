using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.PE;
using AegisPC.Security.Detection;
using AegisPC.Security.PE;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class DeepPeAnalyzerTests : IDisposable
    {
        private readonly string _sandboxDir;
        private readonly DeepPeAnalyzer _analyzer;
        private readonly DeepPeDetector _detector;

        public DeepPeAnalyzerTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "AegisPeTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_sandboxDir);
            _analyzer = new DeepPeAnalyzer();
            _detector = new DeepPeDetector(_analyzer);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_sandboxDir))
                {
                    Directory.Delete(_sandboxDir, recursive: true);
                }
            }
            catch { }
        }

        [Fact]
        public void Test_NonPeFile_ReturnsNotPe()
        {
            var textBytes = Encoding.UTF8.GetBytes("This is just plain text, not a Portable Executable binary.");
            var result = _analyzer.Analyze(textBytes);

            Assert.False(result.IsPeFile);
            Assert.Equal("UNKNOWN", result.ExecutableType);
            Assert.Empty(result.Sections);
        }

        [Fact]
        public void Test_CorruptedMzHeader_ReturnsNotPe()
        {
            var fakeBytes = new byte[1024];
            fakeBytes[0] = 0x4D;
            fakeBytes[1] = 0x00; // Corrupted, not 'MZ' (0x5A)

            var result = _analyzer.Analyze(fakeBytes);
            Assert.False(result.IsPeFile);
        }

        [Fact]
        public async Task Test_RealWindowsSystemPe_DeepAnalysis()
        {
            // Analyze real Windows binary (explorer.exe in C:\Windows)
            var systemExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
            if (!File.Exists(systemExe))
            {
                systemExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            }

            if (File.Exists(systemExe))
            {
                var result = await _analyzer.AnalyzeAsync(systemExe);

                Assert.True(result.IsPeFile, "Windows System binary must be recognized as valid PE.");
                Assert.True(result.Sections.Count > 0, "PE must have sections (.text, .data, etc.)");
                Assert.Contains(result.Sections, s => s.Name.Contains(".text", StringComparison.OrdinalIgnoreCase));
                Assert.True(result.Certificate.IsSigned, "System binary must be digitally signed.");
                Assert.True(result.Certificate.IsMicrosoftTrusted, "System binary must be Microsoft trusted.");
                Assert.False(result.HasWritableExecutableSection, "Legitimate system binary must NOT have W+X anomalies.");
            }
        }

        [Fact]
        public async Task Test_SyntheticWxSection_DetectedAsAnomaly()
        {
            // Build a synthetic PE with a W+X section
            var peBytes = CreateSyntheticPeBinary(hasWxSection: true, hasTlsCallback: false, isPackerName: false);
            var pePath = Path.Combine(_sandboxDir, "wx_payload.exe");
            await File.WriteAllBytesAsync(pePath, peBytes);

            var result = await _analyzer.AnalyzeAsync(pePath);

            Assert.True(result.IsPeFile);
            Assert.True(result.HasWritableExecutableSection, "W+X section anomaly must be detected.");
            Assert.Contains(result.Sections, s => s.IsWritableAndExecutable);
            Assert.Contains(result.Anomalies, a => a.Contains("W+X Anomalisi"));
        }

        [Fact]
        public async Task Test_SyntheticPackerSection_Detected()
        {
            // Build a synthetic PE with a UPX0 section name
            var peBytes = CreateSyntheticPeBinary(hasWxSection: false, hasTlsCallback: false, isPackerName: true);
            var pePath = Path.Combine(_sandboxDir, "upx_packed.exe");
            await File.WriteAllBytesAsync(pePath, peBytes);

            var result = await _analyzer.AnalyzeAsync(pePath);

            Assert.True(result.IsPeFile);
            Assert.True(result.PackerIndicators.Count > 0, "UPX packer indicator must be detected.");
            Assert.Contains(result.PackerIndicators, p => p.Contains("UPX0"));
        }

        [Fact]
        public async Task Test_DeepPeDetector_Plugin_EmitsSecurityEvidences()
        {
            var peBytes = CreateSyntheticPeBinary(hasWxSection: true, hasTlsCallback: true, isPackerName: true);
            var pePath = Path.Combine(_sandboxDir, "complex_anomaly.exe");
            await File.WriteAllBytesAsync(pePath, peBytes);

            var context = new DetectionContext
            {
                FilePath = pePath,
                FileSize = peBytes.Length,
                LastWriteTimeUtc = DateTime.UtcNow
            };

            var evidences = (await _detector.EvaluateAsync(context)).ToList();

            Assert.True(evidences.Count >= 2, "Plugin must emit multiple fine-grained security evidences.");
            Assert.Contains(evidences, e => e.RuleName == "PE_WX_SECTION_DETECTED");
            Assert.Contains(evidences, e => e.RuleName == "PE_KNOWN_PACKER_SECTION");
            Assert.All(evidences, e => Assert.Equal(EvidenceCategory.StaticPeStructure, e.Category));
        }

        [Fact]
        public async Task Test_DetectionHub_IntegratesDeepPeDetector_ProducesAggregatedVerdict()
        {
            var hub = new DetectionHub();
            hub.RegisterDetector(_detector);

            var peBytes = CreateSyntheticPeBinary(hasWxSection: true, hasTlsCallback: false, isPackerName: true);
            var pePath = Path.Combine(_sandboxDir, "hub_test.exe");
            await File.WriteAllBytesAsync(pePath, peBytes);

            var context = new DetectionContext
            {
                FilePath = pePath,
                FileSize = peBytes.Length,
                LastWriteTimeUtc = DateTime.UtcNow
            };

            var verdict = await hub.EvaluateAsync(context);

            Assert.True(verdict.RiskScore >= 35, $"Risk score must reflect PE anomalies (Actual: {verdict.RiskScore})");
            Assert.Contains(verdict.Evidences, e => e.Category == EvidenceCategory.StaticPeStructure);
            Assert.Contains(verdict.Evidences, e => e.RuleName == "PE_WX_SECTION_DETECTED");
        }

        /// <summary>
        /// Testler için standartlara uygun sentetik 32-bit PE ikilisi üretir.
        /// </summary>
        private static byte[] CreateSyntheticPeBinary(bool hasWxSection, bool hasTlsCallback, bool isPackerName)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            // 1. DOS Header
            bw.Write((byte)'M'); bw.Write((byte)'Z'); // e_magic
            ms.Position = 0x3C;
            bw.Write((uint)0x80); // e_lfanew -> PE Header offset

            // DOS Stub
            while (ms.Position < 0x80) bw.Write((byte)0x00);

            // 2. PE Header
            bw.Write((byte)'P'); bw.Write((byte)'E'); bw.Write((byte)0); bw.Write((byte)0); // Signature "PE\0\0"

            // 3. File Header
            bw.Write((ushort)0x014C); // Machine: IMAGE_FILE_MACHINE_I386
            bw.Write((ushort)2);      // NumberOfSections: 2
            bw.Write((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds()); // TimeDateStamp
            bw.Write((uint)0);        // PointerToSymbolTable
            bw.Write((uint)0);        // NumberOfSymbols
            bw.Write((ushort)0xE0);   // SizeOfOptionalHeader
            bw.Write((ushort)0x0102); // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

            // 4. Optional Header (PE32)
            bw.Write((ushort)0x010B); // Magic: PE32 (0x10B)
            bw.Write((byte)14);       // MajorLinkerVersion
            bw.Write((byte)0);        // MinorLinkerVersion
            bw.Write((uint)0x1000);   // SizeOfCode
            bw.Write((uint)0x1000);   // SizeOfInitializedData
            bw.Write((uint)0);        // SizeOfUninitializedData
            bw.Write((uint)0x1000);   // AddressOfEntryPoint
            bw.Write((uint)0x1000);   // BaseOfCode
            bw.Write((uint)0x2000);   // BaseOfData

            // Windows-Specific Fields
            bw.Write((uint)0x00400000); // ImageBase
            bw.Write((uint)0x1000);     // SectionAlignment
            bw.Write((uint)0x200);      // FileAlignment
            bw.Write((ushort)6);        // MajorOperatingSystemVersion
            bw.Write((ushort)0);        // MinorOperatingSystemVersion
            bw.Write((ushort)0);        // MajorImageVersion
            bw.Write((ushort)0);        // MinorImageVersion
            bw.Write((ushort)6);        // MajorSubsystemVersion
            bw.Write((ushort)0);        // MinorSubsystemVersion
            bw.Write((uint)0);          // Win32VersionValue
            bw.Write((uint)0x4000);     // SizeOfImage
            bw.Write((uint)0x400);      // SizeOfHeaders
            bw.Write((uint)0);          // CheckSum
            bw.Write((ushort)2);        // Subsystem: IMAGE_SUBSYSTEM_WINDOWS_GUI
            bw.Write((ushort)0x8140);   // DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
            bw.Write((uint)0x100000);   // SizeOfStackReserve
            bw.Write((uint)0x1000);     // SizeOfStackCommit
            bw.Write((uint)0x100000);   // SizeOfHeapReserve
            bw.Write((uint)0x1000);     // SizeOfHeapCommit
            bw.Write((uint)0);          // LoaderFlags
            bw.Write((uint)16);         // NumberOfRvaAndSizes

            // Data Directories (16 entries * 8 bytes = 128 bytes)
            for (int i = 0; i < 16; i++)
            {
                if (i == 9 && hasTlsCallback) // IMAGE_DIRECTORY_ENTRY_TLS
                {
                    bw.Write((uint)0x3000); // VirtualAddress
                    bw.Write((uint)0x20);   // Size
                }
                else
                {
                    bw.Write((uint)0); // VirtualAddress
                    bw.Write((uint)0); // Size
                }
            }

            // 5. Section Headers (2 Sections * 40 bytes)
            // Section 1: .text (or UPX0)
            byte[] sec1Name = new byte[8];
            var nameStr = isPackerName ? "UPX0" : ".text";
            Encoding.ASCII.GetBytes(nameStr).CopyTo(sec1Name, 0);
            bw.Write(sec1Name);
            bw.Write((uint)0x1000); // VirtualSize
            bw.Write((uint)0x1000); // VirtualAddress
            bw.Write((uint)0x200);  // SizeOfRawData
            bw.Write((uint)0x400);  // PointerToRawData
            bw.Write((uint)0);      // PointerToRelocations
            bw.Write((uint)0);      // PointerToLinenumbers
            bw.Write((ushort)0);    // NumberOfRelocations
            bw.Write((ushort)0);    // NumberOfLinenumbers
            
            // Characteristics: Execute + Read (+ Write if W+X requested)
            uint sec1Chars = 0x60000020; // CNT_CODE | MEM_EXECUTE | MEM_READ
            if (hasWxSection)
            {
                sec1Chars |= 0x80000000; // + MEM_WRITE (W+X Anomaly!)
            }
            bw.Write(sec1Chars);

            // Section 2: .data
            byte[] sec2Name = new byte[8];
            Encoding.ASCII.GetBytes(".data").CopyTo(sec2Name, 0);
            bw.Write(sec2Name);
            bw.Write((uint)0x1000); // VirtualSize
            bw.Write((uint)0x2000); // VirtualAddress
            bw.Write((uint)0x200);  // SizeOfRawData
            bw.Write((uint)0x600);  // PointerToRawData
            bw.Write((uint)0);      // PointerToRelocations
            bw.Write((uint)0);      // PointerToLinenumbers
            bw.Write((ushort)0);    // NumberOfRelocations
            bw.Write((ushort)0);    // NumberOfLinenumbers
            bw.Write((uint)0xC0000040); // CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE

            // Pad to Header Size (0x400)
            while (ms.Position < 0x400) bw.Write((byte)0x00);

            // Section 1 Raw Data (.text code)
            for (int i = 0; i < 0x200; i++) bw.Write((byte)0x90); // NOP sled

            // Section 2 Raw Data (.data)
            for (int i = 0; i < 0x200; i++) bw.Write((byte)0xCC); // INT 3 padding

            return ms.ToArray();
        }
    }
}
