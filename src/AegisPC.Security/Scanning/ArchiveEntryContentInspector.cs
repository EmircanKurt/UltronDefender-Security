using AegisPC.Contracts.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Detection.YaraEngine;

namespace AegisPC.Security.Scanning;

/// <summary>Maps bounded decompressed content with the same static/script/rule semantics as loose content.</summary>
internal static class ArchiveEntryContentInspector
{
    internal static async Task<(bool IsText, List<SecurityEvidence> Evidence, string? Gap)> InspectAsync(
        byte[]? ruleInput, byte[]? testContent, List<YaraMatch> rules, string memberName, string sha256, CancellationToken cancellationToken)
    {
            bool isText = ruleInput != null && ContentRuleSemantics.IsBoundedText(ruleInput);
            var textEvidence = isText ? ScriptHeuristicDetector.EvaluateText(ContentRuleSemantics.DecodeText(ruleInput!),
                new DetectionContext { FilePath = memberName, SHA256 = sha256 }, cancellationToken) : new List<SecurityEvidence>();
            textEvidence.AddRange(YaraDetector.BuildEvidence(rules,
                new DetectionContext { FilePath = memberName, SHA256 = sha256 }, isText,
                testContent != null && MalwareSignatureDatabase.CheckCanonicalTestContent(testContent).IsMatched));
            string? gap = null;
            if (ruleInput == null) gap = "Üye hash/desen incelemesi yapıldı; yapı/script incelemesi kısmi, tampon bütçesi dışında.";
            else
            {
                using var memberSource = new MemoryStream(ruleInput, writable: false);
                var classification = await new FileContentClassifier().ClassifyAsync(memberSource, Path.GetExtension(memberName), cancellationToken);
                if (!classification.IsComplete) gap = "Üye yapısı kısmi: " + string.Join("; ", classification.CoverageLimitations);
                if (classification.Formats.Contains(AegisPC.Core.Models.FileContentFormat.PortableExecutable))
                {
                    // Never extract or execute: reuse the loose-file static PE rule mapping over bounded bytes.
                    var memberContext = new DetectionContext { FilePath = memberName, SHA256 = sha256 };
                    var analyzer = new AegisPC.Security.PE.DeepPeAnalyzer();
                    var staticBytes = ruleInput.Length > 2 * 1024 * 1024 ? ruleInput.AsSpan(0, 2 * 1024 * 1024).ToArray() : ruleInput;
                    var pe = analyzer.Analyze(staticBytes, memberName);
                    pe.IsStaticInspectionComplete = ruleInput.Length == staticBytes.Length;
                    textEvidence.AddRange(new AegisPC.Security.PE.DeepPeDetector(analyzer).BuildEvidence(pe, memberContext, includeCertificate: false));
                    gap = "Üye statik PE/hash/kural incelemesi yapıldı; dosya tabanlı Authenticode, diğer PE ve davranış adaptörleri kapsayıcı içinde çalıştırılmadı.";
                    if (memberContext.CoverageLimitations.Count > 0) gap += " " + string.Join("; ", memberContext.CoverageLimitations);
                }
            }
        return (isText, textEvidence, gap);
    }
}

