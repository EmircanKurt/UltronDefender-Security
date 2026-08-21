using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.PE;
using AegisPC.Security.Scanning;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Tests
{
    public class SetupDiagnostics
    {
        private readonly ITestOutputHelper _output;

        public SetupDiagnostics(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public async Task Diagnose_UltronDefender_Setup_File()
        {
            string setupPath = @"c:\Users\PC\Documents\gemini virüs program\UltronDefender_Setup_v3.0.exe";
            if (!File.Exists(setupPath))
            {
                _output.WriteLine("Setup file not found: " + setupPath);
                return;
            }

            var fileInfo = new FileInfo(setupPath);
            _output.WriteLine("=== SETUP FILE METRICS ===");
            _output.WriteLine($"Path:       {fileInfo.FullName}");
            _output.WriteLine($"Size:       {fileInfo.Length:N0} bytes ({fileInfo.Length / (1024.0 * 1024.0):F2} MB)");
            _output.WriteLine($"Created:    {fileInfo.CreationTimeUtc:yyyy-MM-dd HH:mm:ss} UTC");
            _output.WriteLine($"Modified:   {fileInfo.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC");

            var hashService = new HashService();
            string sha256 = await hashService.ComputeSha256Async(setupPath);
            _output.WriteLine($"SHA256:     {sha256}");

            var sigVerifier = new SignatureVerifier();
            var sig = await sigVerifier.VerifySignatureAsync(setupPath);
            _output.WriteLine($"Signed:     {sig.IsSigned}");
            _output.WriteLine($"Valid Sig:  {sig.IsValid}");
            _output.WriteLine($"Publisher:  {sig.Publisher ?? "(None - Unsigned)"}");

            double entropy = await EntropyCalculator.CalculateEntropyAsync(setupPath);
            _output.WriteLine($"Entropy:    {entropy:F4} / 8.0000");

            var peAnalysis = PeAnalyzer.Analyze(setupPath);
            _output.WriteLine($"Type:          {peAnalysis.ExecutableType}");

            // Risk Engine Scoring
            var riskEngine = new RiskScoringEngine();
            var fileAnalysis = new FileAnalysisResult
            {
                FilePath = setupPath,
                FileName = fileInfo.Name,
                SHA256 = sha256,
                FileSize = fileInfo.Length,
                CreatedAt = fileInfo.CreationTimeUtc,
                ModifiedAt = fileInfo.LastWriteTimeUtc,
                IsSigned = sig.IsSigned,
                SignaturePublisher = sig.Publisher,
                SignatureValid = sig.IsValid,
                IsExecutable = true,
                ExecutableType = peAnalysis.ExecutableType,
                Entropy = entropy,
                IsKnownLocation = PathHelper.IsKnownSafePath(setupPath)
            };

            var (score, riskLevel, reasons) = await riskEngine.CalculateRiskScoreAsync(fileAnalysis);
            _output.WriteLine($"\n=== RISK SCORING ENGINE VERDICT ===");
            _output.WriteLine($"Total Score: {score}/100");
            _output.WriteLine($"Risk Level:  {riskLevel}");
            _output.WriteLine("Reasons:");
            foreach (var r in reasons)
            {
                _output.WriteLine(" * " + r);
            }

            // DetectionHub Evaluation
            var detectionHub = DetectionHubFactory.CreateDefault(hashService, sigVerifier);
            var context = new DetectionContext
            {
                FilePath = setupPath,
                FileSize = fileInfo.Length,
                SHA256 = sha256,
                CreationTimeUtc = fileInfo.CreationTimeUtc,
                LastWriteTimeUtc = fileInfo.LastWriteTimeUtc
            };
            var hubResult = await detectionHub.EvaluateAsync(context);
            _output.WriteLine($"\n=== DETECTIONHUB MULTI-PLUGIN VERDICT ===");
            _output.WriteLine($"Hub Score:       {hubResult.RiskScore}/100");
            _output.WriteLine($"Hub Verdict:     {hubResult.Verdict}");
            _output.WriteLine($"Hub Action:      {hubResult.RecommendedAction}");
            _output.WriteLine($"Total Evidences: {hubResult.Evidences.Count}");
            foreach (var ev in hubResult.Evidences)
            {
                _output.WriteLine($" -> [{ev.Category}] [{ev.RuleName}] (Score: +{ev.ScoreContribution}, Conf: {ev.Confidence}) - {ev.Description}");
            }
        }
    }
}
