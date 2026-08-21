using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests
{
    public class GameCrackWatchdogTests
    {
        [Fact]
        public void Legitimate_Game_Save_Files_Are_Allowed()
        {
            var watchdog = new GameCrackWatchdogShield();
            var gameExe = @"C:\Games\Grand Theft Auto V\GTA5.exe";
            var saveFile = @"C:\Users\PC\Documents\Rockstar Games\GTA V\Profiles\savegame.dat";

            var result = watchdog.EvaluateActivity(gameExe, saveFile);

            Assert.False(result.IsMalicious);
            Assert.Equal(WatchdogActionVerdict.LegitimateGameFile, result.Verdict);
            Assert.Equal(0, result.RiskScore);
        }

        [Fact]
        public void Game_Process_Stealing_Browser_Credentials_Is_Blocked()
        {
            var watchdog = new GameCrackWatchdogShield();
            var gameExe = @"C:\Users\PC\Downloads\BeamNG.drive\Bin64\BeamNG.drive.x64.exe";
            var targetCredential = @"C:\Users\PC\AppData\Local\Google\Chrome\User Data\Default\Login Data";

            var result = watchdog.EvaluateActivity(gameExe, targetCredential);

            Assert.True(result.IsMalicious);
            Assert.Equal(WatchdogActionVerdict.CredentialStealingAttempt, result.Verdict);
            Assert.True(result.RiskScore >= 90);
        }

        [Fact]
        public void Game_Process_Dropping_Startup_Payload_Is_Blocked()
        {
            var watchdog = new GameCrackWatchdogShield();
            var gameExe = @"C:\Games\Cyberpunk 2077\bin\x64\Cyberpunk2077.exe";
            var startupPayload = @"C:\Users\PC\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\backdoor.bat";

            var result = watchdog.EvaluateActivity(gameExe, startupPayload);

            Assert.True(result.IsMalicious);
            Assert.Equal(WatchdogActionVerdict.PersistenceTamper, result.Verdict);
            Assert.True(result.RiskScore >= 90);
        }

        [Fact]
        public void Game_Process_Dropping_Cross_Folder_Exe_In_Temp_Is_Blocked()
        {
            var watchdog = new GameCrackWatchdogShield();
            var gameExe = @"C:\Games\GameCrack\game.exe";
            var tempExe = @"C:\Users\PC\AppData\Local\Temp\hidden_miner.exe";

            var result = watchdog.EvaluateActivity(gameExe, tempExe);

            Assert.True(result.IsMalicious);
            Assert.Equal(WatchdogActionVerdict.SuspiciousCrossFolderDrop, result.Verdict);
            Assert.True(result.RiskScore >= 80);
        }

        [Fact]
        public async Task Csv_Dde_Formula_Injection_Is_Detected()
        {
            var detector = new ScriptHeuristicDetector();
            var tempCsv = Path.Combine(Path.GetTempPath(), $"test_dde_{Guid.NewGuid():N}.csv");
            try
            {
                await File.WriteAllTextAsync(tempCsv, "Name,Age,Formula\nJohn,30,=cmd|'/C calc.exe'!A1\n");

                var context = new DetectionContext { FilePath = tempCsv };
                var evidences = await detector.EvaluateAsync(context);

                Assert.Contains(evidences, e => e.RuleName == "Script.CsvDdeFormulaInjection");
            }
            finally
            {
                if (File.Exists(tempCsv)) File.Delete(tempCsv);
            }
        }
    }
}