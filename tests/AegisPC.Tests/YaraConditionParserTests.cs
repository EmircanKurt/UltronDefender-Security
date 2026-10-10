using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Detection.YaraEngine;
using Xunit;

namespace AegisPC.Tests
{
    public class YaraConditionParserTests : IDisposable
    {
        private readonly string _tempRulesDir;
        private readonly YaraEngine _yaraEngine;

        public YaraConditionParserTests()
        {
            _tempRulesDir = Path.Combine(Path.GetTempPath(), $"AegisPC_YaraConditionTest_{Guid.NewGuid():N}");
            Directory.CreateDirectory(_tempRulesDir);
            _yaraEngine = new YaraEngine(_tempRulesDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempRulesDir))
                {
                    Directory.Delete(_tempRulesDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public void YaraConditionParser_AndCondition_MatchesOnlyWhenBothPresent()
        {
            // P0 Finding 2: "A ve B koşulunda yalnızca A bulunan deneme yine eşleşti" bug fix verification
            var ast = YaraConditionParser.Parse("$a and $b", new[] { "$a", "$b" });

            var onlyA = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "$a" };
            var onlyB = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "$b" };
            var both = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "$a", "$b" };
            var none = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            Assert.False(ast.Evaluate(onlyA, 2), "Condition '$a and $b' MUST NOT match when only $a is present!");
            Assert.False(ast.Evaluate(onlyB, 2), "Condition '$a and $b' MUST NOT match when only $b is present!");
            Assert.False(ast.Evaluate(none, 2), "Condition '$a and $b' MUST NOT match when neither is present!");
            Assert.True(ast.Evaluate(both, 2), "Condition '$a and $b' MUST match when both $a and $b are present!");
        }

        [Fact]
        public void YaraConditionParser_OrCondition_MatchesWhenEitherPresent()
        {
            var ast = YaraConditionParser.Parse("$a or $b", new[] { "$a", "$b" });

            var onlyA = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "$a" };
            var onlyB = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "$b" };
            var none = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            Assert.True(ast.Evaluate(onlyA, 2));
            Assert.True(ast.Evaluate(onlyB, 2));
            Assert.False(ast.Evaluate(none, 2));
        }

        [Fact]
        public void YaraConditionParser_NotAndPrecedence_EvaluatesAccurately()
        {
            var ast = YaraConditionParser.Parse("($a or $b) and not $c", new[] { "$a", "$b", "$c" });

            var matchA = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "$a" };
            var matchAAndC = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "$a", "$c" };

            Assert.True(ast.Evaluate(matchA, 3));
            Assert.False(ast.Evaluate(matchAAndC, 3), "not $c must negate the condition when $c is present!");
        }

        [Fact]
        public void YaraConditionParser_AllOfThem_RequiresAllPatterns()
        {
            var ast = YaraConditionParser.Parse("all of them", new[] { "$s1", "$s2", "$s3" });

            var twoOfThree = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "$s1", "$s2" };
            var allThree = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "$s1", "$s2", "$s3" };

            Assert.False(ast.Evaluate(twoOfThree, 3));
            Assert.True(ast.Evaluate(allThree, 3));
        }

        [Fact]
        public void YaraConditionParser_NOfSet_EvaluatesExactThreshold()
        {
            var ast = YaraConditionParser.Parse("2 of ($s1, $s2, $s3)", new[] { "$s1", "$s2", "$s3" });

            var oneMatched = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "$s1" };
            var twoMatched = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "$s1", "$s3" };

            Assert.False(ast.Evaluate(oneMatched, 3));
            Assert.True(ast.Evaluate(twoMatched, 3));
        }

        [Fact]
        public void YaraConditionParser_UnsupportedOrInvalidSyntax_ThrowsParseException()
        {
            // Desteklenmeyen veya geçersiz sözdizimi sessizce geçiştirilmemeli, kural yüklenmemelidir
            Assert.Throws<YaraConditionParseException>(() =>
                YaraConditionParser.Parse("filesize < 10MB", new[] { "$a" }));

            Assert.Throws<YaraConditionParseException>(() =>
                YaraConditionParser.Parse("A ve B", new[] { "$a", "$b" }));

            Assert.Throws<YaraConditionParseException>(() =>
                YaraConditionParser.Parse("$undefined_id and $a", new[] { "$a" }));
        }

        [Fact]
        public async Task YaraEngine_RuleWithAndCondition_DoesNotTriggerOnPartialMatch()
        {
            string customRule = @"
rule Test_Strict_And_Condition
{
    meta:
        description = ""Requires both indicator A and B""
        severity = 80
    strings:
        $indicatorA = ""CRITICAL_INDICATOR_ALPHA""
        $indicatorB = ""CRITICAL_INDICATOR_BETA""
    condition:
        $indicatorA and $indicatorB
}
";
            string rulePath = Path.Combine(_tempRulesDir, "custom_and.yar");
            await File.WriteAllTextAsync(rulePath, customRule, Encoding.UTF8);
            _yaraEngine.ReloadRules();

            // Sadece A içeren tampon
            byte[] onlyABuffer = Encoding.ASCII.GetBytes("Prefix content with CRITICAL_INDICATOR_ALPHA only.");
            var matchesA = await _yaraEngine.ScanBufferAsync(onlyABuffer, "sample.bin");
            Assert.DoesNotContain(matchesA, m => m.RuleName == "Test_Strict_And_Condition");

            // Hem A hem B içeren tampon
            byte[] bothBuffer = Encoding.ASCII.GetBytes("Prefix content with CRITICAL_INDICATOR_ALPHA and also CRITICAL_INDICATOR_BETA.");
            var matchesBoth = await _yaraEngine.ScanBufferAsync(bothBuffer, "sample.bin");
            Assert.Contains(matchesBoth, m => m.RuleName == "Test_Strict_And_Condition");
        }

        [Fact]
        public async Task YaraEngine_InvalidConditionRule_DoesNotUnloadValidRules()
        {
            int initialCount = _yaraEngine.LoadedRuleCount;
            Assert.True(initialCount >= 3);

            // Bozuk/desteklenmeyen kural yaz
            string brokenRule = @"
rule Broken_Rule
{
    meta:
        description = ""Invalid syntax rule""
    strings:
        $s1 = ""test""
    condition:
        unsupported_module.is_threat()
}
";
            string brokenPath = Path.Combine(_tempRulesDir, "broken.yar");
            await File.WriteAllTextAsync(brokenPath, brokenRule, Encoding.UTF8);

            // Yeniden yükle: bozuk kural atlanmalı, önceki geçerli kurallar korunmalıdır
            _yaraEngine.ReloadRules();
            Assert.True(_yaraEngine.LoadedRuleCount >= initialCount);
        }

        [Fact]
        public async Task YaraDetector_BenignLectureNotes_Sekurlsa_ProducesZeroAutoQuarantine()
        {
            // P0 Finding 1: Zararsız ders metnindeki sekurlsa::logonpasswords 100 puanlık zararlı eşleşmesi üretmemeli
            string lectureNotesFile = Path.Combine(_tempRulesDir, "cybersecurity_101_notes.txt");
            string docContent = @"
Ders Notları: Windows Güvenliği ve Kimlik Doğrulama Mekanizmaları
Örnek Mimikatz Saldırısı İncelemesi:
Saldırganlar bellekten kimlik bilgilerini çekmek için sekurlsa::logonpasswords komutunu çalıştırabilir.
Bunu engellemek için Credential Guard ve LSA koruması devreye alınmalıdır.
";
            await File.WriteAllTextAsync(lectureNotesFile, docContent, Encoding.UTF8);

            try
            {
                var detector = new YaraDetector(_yaraEngine);
                var context = new DetectionContext
                {
                    FilePath = lectureNotesFile,
                    FileSize = new FileInfo(lectureNotesFile).Length
                };

                var evidences = (await detector.EvaluateAsync(context)).ToList();

                // Kanıt oluşsa bile:
                // 1. Asla StaticSignature olmamalı (ScriptHeuristic / DocumentationText olmalı)
                // 2. Asla Absolute Confidence olmamalı (Low olmalı)
                // 3. Puanı 100 olmamalı (Düşük olmalı)
                foreach (var ev in evidences)
                {
                    Assert.NotEqual(EvidenceConfidence.Absolute, ev.Confidence);
                    Assert.True(ev.ScoreContribution <= 25, $"Ders notu için puan katkısı en fazla 25 olmalı, bulunan: {ev.ScoreContribution}");
                }

                // DetectionHub ile bütünleşik değerlendirme:
                var hub = DetectionHubFactory.CreateDefault(yaraEngine: _yaraEngine);
                var detectionResult = await hub.EvaluateAsync(context);

                // Kesin zararlı (ConfirmedMalicious) VEYA Karantina (BlockAndQuarantine) ÇIKMAMALI!
                Assert.NotEqual(DetectionVerdict.ConfirmedMalicious, detectionResult.Verdict);
                Assert.NotEqual(DetectionPolicy.BlockAndQuarantine, detectionResult.RecommendedPolicy);
                Assert.True(detectionResult.RiskScore < 50, $"Ders notunun nihai risk puanı 50'nin altında olmalıdır. Hesaplanan: {detectionResult.RiskScore}");
            }
            finally
            {
                if (File.Exists(lectureNotesFile)) File.Delete(lectureNotesFile);
            }
        }
    }
}
