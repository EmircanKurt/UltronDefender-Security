using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.Detection.Detectors
{
    public class ScriptHeuristicDetector : IDetectorPlugin
    {
        public string DetectorId => "Detector.ScriptHeuristic";
        public string DisplayName => "Betik ve Komut Dosyasi Sezgisel Analizoru";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.ScriptHeuristic;
        public int Priority => 25;
        public bool IsEnabled { get; set; } = true;

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
            ("dGFza2tpbGwuKig/OnVsdHJvbnxhZWdpc3xtc21wZW5nfGRlZmVuZGVyKQ==", "Script.AvKillAttempt", "Antivirüs Kapatma / Sonlandırma Girişimi (taskkill /im Ultron)", 65, EvidenceConfidence.Absolute),
            ("YW1zaUluaXRGYWlsZWR8QW1zaVV0aWxz", "Script.AmsiReference", "AMSI ile ilgili ad görüldü; atlatma veya çalıştırma kanıtlanmadı.", 10, EvidenceConfidence.Low),
            ("VmlydHVhbEFsbG9jfFdyaXRlUHJvY2Vzc01lbW9yeXxDcmVhdGVSZW1vdGVUaHJlYWQ=", "Script.ProcessMemoryReference", "Süreç belleği API adı görüldü; çağrı veya enjeksiyon kanıtlanmadı.", 10, EvidenceConfidence.Low),
            ("cnVuZGxsMzIoXC5leGUpP1xzKy4qKD86amF2YXNjcmlwdHx2YnNjcmlwdCk6", "Script.Rundll32Script", "Rundll32 uzerinden Zararli Script Yurutme", 65, EvidenceConfidence.High),
            ("bXNodGEoXC5leGUpP1xzK2h0dHBzPzo=", "Script.MshtaRemoteExecution", "Mshta ile Uzaktan Zararli Kod Calistirma", 55, EvidenceConfidence.High),
            ("Y2VydHV0aWwoXC5leGUpP1xzKy4qLXVybGNhY2hlLipodHRwcz86", "Script.CertutilDownload", "Certutil ile Uzaktan Dosya Indirme (LOLBin)", 45, EvidenceConfidence.High),
            ("Y29tc3Zjc1wuZGxsLipNaW5pRHVtcA==", "Script.ComsvcsLsassDump", "LSASS Parola Hafiza Dokumu Girisimi (comsvcs MiniDump)", 80, EvidenceConfidence.Absolute),
            ("cmVnKFwuZXhlKT9ccytzYXZlXHMraGtsbVxcKD86c2FtfHN5c3RlbSk=", "Script.RegSaveCredentialHive", "SAM/SYSTEM Parola Kovanini Kopyalama Girisimi", 80, EvidenceConfidence.Absolute),
            ("U2V0LU1wUHJlZmVyZW5jZVxzKy4qLURpc2FibGVSZWFsdGltZU1vbml0b3Jpbmc=", "Script.DisableDefender", "Defender Gercek Zamanli Korumayi Devre Disi Birakma", 85, EvidenceConfidence.Absolute),
            ("bmV0c2goXC5leGUpP1xzK2FkdmZpcmV3YWxsXHMrc2V0XHMrYWxscHJvZmlsZXNccytzdGF0ZVxzK29mZg==", "Script.DisableFirewall", "Guvenlik Duvarini Kapatma Girisimi", 80, EvidenceConfidence.Absolute)
        };

        /// <summary>Inspects bounded text candidates regardless of extension or directory; regex matches are heuristic evidence only.</summary>
        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();
            if (string.IsNullOrEmpty(context.FilePath) || !File.Exists(context.FilePath))
            {
                return list;
            }

            var classification = context.ContentClassification ?? context.SharedScan?.ContentClassification;
            if (classification == null)
            {
                using var source = new FileStream(context.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                classification = await new FileContentClassifier().ClassifyAsync(source, Path.GetExtension(context.FilePath), cancellationToken);
                context.ContentClassification = classification;
                if (context.SharedScan != null) context.SharedScan.ContentClassification = classification;
                context.CoverageLimitations.AddRange(classification.CoverageLimitations);
            }
            if (!classification.Formats.Contains(FileContentFormat.Text) && !classification.Formats.Contains(FileContentFormat.ScriptCandidate)) return list;

            try
            {
                string content;
                using (var fs = new FileStream(context.FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var reader = new StreamReader(fs, Encoding.UTF8, true, 4096, true))
                {
                    char[] buffer = new char[Math.Min(1024 * 1024, (int)Math.Min(int.MaxValue, fs.Length))];
                    int read = await reader.ReadBlockAsync(buffer.AsMemory(), cancellationToken);
                    content = new string(buffer, 0, read);

                    // Padding bypass koruması: Dosya 1MB'dan büyükse son 256KB'yı da tara
                    if (fs.Length > 1024 * 1024)
                    {
                        var tailSize = Math.Min(256 * 1024, fs.Length - 1024 * 1024);
                        fs.Seek(-tailSize, SeekOrigin.End);
                        var tailBuffer = new byte[tailSize];
                        int tailRead = await fs.ReadAsync(tailBuffer.AsMemory(), cancellationToken);
                        var tailContent = System.Text.Encoding.UTF8.GetString(tailBuffer, 0, tailRead);
                        content = content + "\n" + tailContent; // Append tail content for scanning
                        if (fs.Length > 1024 * 1024 + 256 * 1024)
                            context.CoverageLimitations.Add("Script heuristic inspected bounded prefix/tail samples; the middle content was not inspected by this detector.");
                    }
                }

                list.AddRange(EvaluateText(content, context, cancellationToken));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                // The shared hub records this detector failure instead of silently publishing clean coverage.
                throw new IOException("Bounded text heuristic inspection could not complete.", ex);
            }

            return list;
        }

        internal static List<SecurityEvidence> EvaluateText(string content, DetectionContext context, CancellationToken cancellationToken)
        {
            var list = new List<SecurityEvidence>();
                foreach (var (patB64, rule, desc, score, conf) in ScriptPatterns)
                {
                    var pattern = Dec(patB64);
                    cancellationToken.ThrowIfCancellationRequested();
                    if (Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
                    {
                        list.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.ScriptHeuristic,
                            SourceDetector = "Betik ve Komut Dosyasi Sezgisel Analizoru",
                            RuleName = rule,
                            Description = desc,
                            ScoreContribution = score,
                            Confidence = conf,
                            Nature = rule is "Script.AmsiReference" or "Script.ProcessMemoryReference"
                                ? EvidenceNature.Capability : EvidenceNature.Heuristic,
                            FeatureIdentity = rule is "Script.AmsiReference" ? "AMSI.Reference"
                                : rule is "Script.ProcessMemoryReference" ? "ProcessMemory.Reference" : string.Empty,
                            FilePath = context.FilePath,
                            SHA256 = context.SHA256,
                            ProcessId = context.ProcessId,
                            ParentProcessId = context.ParentProcessId
                        });
                    }
                }
            return list;
        }
    }
}
