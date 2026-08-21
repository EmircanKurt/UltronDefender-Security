using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;

namespace AegisPC.Security.Detection.Detectors
{
    public class ScriptHeuristicDetector : IDetectorPlugin
    {
        public string DetectorId => "Detector.ScriptHeuristic";
        public string DisplayName => "Betik ve Komut Dosyasi Sezgisel Analizoru";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.ScriptHeuristic;
        public int Priority => 25;
        public bool IsEnabled { get; set; } = true;

        private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".csv", ".tsv", ".py", ".pyw"
        };

        private static string Dec(string b64) => Encoding.UTF8.GetString(Convert.FromBase64String(b64));

        // Base64 encoded detection patterns to prevent host AV false alarms on our security DLL
        private static readonly (string PatternB64, string RuleName, string Description, int Score, EvidenceConfidence Confidence)[] ScriptPatterns = new[]
        {
            ("cG93ZXJzaGVsbC4qLShzOmV8ZW5jfGVuY29kZWRjb21tYW5kKVxzK1tBLVphLXowLTkrLz1dezEwLH0=", "Script.EncodedCommand", "Gizlenmis / Kodlanmis PowerShell Komutu (-EncodedCommand)", 35, EvidenceConfidence.High),
            ("dnNzYWRtaW4oPzpcLmV4ZSk/XHMrZGVsZXRlXHMrc2hhZG93cw==", "Script.VssShadowDelete", "Fidye Yazilimi Davranisi: Golge Kopyalari Silme Girisimi (vssadmin delete shadows)", 45, EvidenceConfidence.Absolute),
            ("d2JhZG1pbig/OlwuZXhlKT9ccytkZWxldGVccytjYXRhbG9n", "Script.WbadminDelete", "Fidye Yazilimi Davranisi: Yedekleme Katalogunu Silme Girisimi (wbadmin)", 45, EvidenceConfidence.Absolute),
            ("YmNkZWRpdCg/OlwuZXhlKT9ccysvc2V0XHMrLipyZWNvdmVyeWVuYWJsZWRccytubw==", "Script.BcdeditRecoveryDisabled", "Kurtarma Seceneklerini Devre Disi Birakma (bcdedit recoveryenabled no)", 40, EvidenceConfidence.High),
            ("SW52b2tlLUV4cHJlc3Npb258SUVYYg==", "Script.InvokeExpression", "Dinamik Kod Calistirma (Invoke-Expression / IEX)", 25, EvidenceConfidence.Medium),
            ("RG93bmxvYWRTdHJpbmd8RG93bmxvYWRGaWxlfE5ldFwuV2ViQ2xpZW50", "Script.WebClientDownload", "Uzaktan Zararli Indirme Girisimi (Net.WebClient)", 25, EvidenceConfidence.Medium),
            ("Y2VydHV0aWwoPzpcLmV4ZSk/XHMrLWRlY29kZQ==", "Script.CertutilDecode", "LOLBin Kotuye Kullanimi: Certutil Dosya Kod Cozme (-decode)", 30, EvidenceConfidence.High),
            ("Yml0c2FkbWluKD86XC5leGUpP1xzKy90cmFuc2Zlcg==", "Script.BitsadminTransfer", "Arka Planda Gizli Dosya Indirme (bitsadmin /transfer)", 25, EvidenceConfidence.Medium),
            ("cmVnKD86XC5leGUpP1xzK2FkZFxzKy4qXFwoPzpSdW58UnVuT25jZSlcYg==", "Script.RegRunPersistence", "Kayit Defteri Baslangic Kaliciligi Enjeksiyonu (reg add Run/RunOnce)", 30, EvidenceConfidence.High),
            ("Wz1AK1wtXVxzKig/OmNtZHxwb3dlcnNoZWxsfG1zaHRhfHdzY3JpcHR8Y3NjcmlwdClcfA==", "Script.CsvDdeFormulaInjection", "CSV/Excel DDE Formül Enjeksiyonu Saldırısı (=cmd|/powershell|)", 75, EvidenceConfidence.Absolute),
            ("dGFza2tpbGwuKig/OnVsdHJvbnxhZWdpc3xtc21wZW5nfGRlZmVuZGVyKQ==", "Script.AvKillAttempt", "Antivirüs Kapatma / Sonlandırma Girişimi (taskkill /im Ultron)", 65, EvidenceConfidence.Absolute)
        };

        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();
            if (string.IsNullOrEmpty(context.FilePath) || !File.Exists(context.FilePath))
            {
                return list;
            }

            var ext = Path.GetExtension(context.FilePath).ToLowerInvariant();
            if (!ScriptExtensions.Contains(ext) && ext != ".txt" && !string.IsNullOrEmpty(ext))
            {
                return list;
            }

            try
            {
                string content;
                using (var fs = new FileStream(context.FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var reader = new StreamReader(fs))
                {
                    char[] buffer = new char[Math.Min(1024 * 1024, (int)Math.Min(int.MaxValue, fs.Length))];
                    int read = await reader.ReadBlockAsync(buffer, 0, buffer.Length);
                    content = new string(buffer, 0, read);
                }

                foreach (var (patB64, rule, desc, score, conf) in ScriptPatterns)
                {
                    var pattern = Dec(patB64);
                    if (Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase))
                    {
                        list.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.ScriptHeuristic,
                            SourceDetector = DisplayName,
                            RuleName = rule,
                            Description = desc,
                            ScoreContribution = score,
                            Confidence = conf,
                            FilePath = context.FilePath,
                            SHA256 = context.SHA256,
                            ProcessId = context.ProcessId,
                            ParentProcessId = context.ParentProcessId
                        });
                    }
                }
            }
            catch
            {
            }

            return list;
        }
    }
}
