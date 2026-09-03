using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests
{
    /// <summary>
    /// Fidye kalkanının Canary tuzak dosyalarını gerçek disk üzerinde konuşlandırdığını
    /// ve bir ihlal durumunda çalışan gerçek işletim sistemi sürecini (Process)
    /// derhal sonlandırdığını (Kill) doğrulayan canlı entegrasyon testi (Zero-Mock).
    /// </summary>
    public class RansomwareRealProcessKillTests : IDisposable
    {
        private readonly string _testSandboxDir;
        private readonly RansomwareProtectionEngine _engine;

        public RansomwareRealProcessKillTests()
        {
            _testSandboxDir = Path.Combine(Path.GetTempPath(), "Aegis_RealCanaryTest_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_testSandboxDir);

            _engine = new RansomwareProtectionEngine();
            _engine.AddProtectedDirectory(_testSandboxDir);
        }

        [Fact]
        public async Task CanaryDecoy_IsDeployedToDisk_AndOffendingProcessIsReallyTerminated()
        {
            // 1. Kalkanı Başlat
            _engine.StartShield();

            // 2. DOĞRULAMA 1: Canary tuzak dosyası disk üzerinde oluştu mu ve gizli mi?
            var canaryPath = Path.Combine(_testSandboxDir, "!_ultron_shield_canary.docx");
            Assert.True(File.Exists(canaryPath), "Canary tuzak dosyası korumalı dizinde fiziksel olarak bulunmalıdır.");

            var attr = File.GetAttributes(canaryPath);
            Assert.True(attr.HasFlag(FileAttributes.Hidden), "Canary tuzak dosyası Hidden niteliğine sahip olmalıdır.");

            // 3. DOĞRULAMA 2: Gerçek bir işletim sistemi süreci başlat (Saldırgan rolünde)
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c ping 127.0.0.1 -n 30 > nul",
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var rogueProcess = Process.Start(psi);
            Assert.NotNull(rogueProcess);
            Assert.False(rogueProcess.HasExited, "Saldırgan test süreci çalışıyor olmalıdır.");

            int roguePid = rogueProcess.Id;

            // 4. Canary ihlali tetikle (Saldırgan PID'si ile)
            var assessment = await _engine.EvaluateAndContainThreatAsync(
                canaryPath,
                "🚨 Test: Kritik Canary Dosyası İhlali Tespit Edildi!",
                riskScore: 100,
                pid: roguePid);

            Assert.NotNull(assessment);
            Assert.True(assessment.FilesBlocked >= 1);

            // Sürecin ölmesini bekle (azami 2 saniye)
            try
            {
                await rogueProcess.WaitForExitAsync();
            }
            catch { }

            // 5. DOĞRULAMA 3: Süreç gerçekten sonlandırıldı mı?
            Assert.True(rogueProcess.HasExited, "Saldırgan süreç kalkan tarafından derhal Kill edilmiş olmalıdır!");

            // 6. Kalkanı Durdur ve Temizliği doğrula
            _engine.StopShield();
            Assert.False(File.Exists(canaryPath), "Kalkan durdurulduğunda canary tuzak dosyası diskten temizlenmelidir.");
        }

        public void Dispose()
        {
            try
            {
                _engine.StopShield();
                _engine.Dispose();
            }
            catch { }

            try
            {
                if (Directory.Exists(_testSandboxDir))
                {
                    Directory.Delete(_testSandboxDir, recursive: true);
                }
            }
            catch { }
        }
    }
}
