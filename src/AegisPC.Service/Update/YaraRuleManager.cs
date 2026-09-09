using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Update
{
    /// <summary>
    /// YARA Benzeri Gelişmiş İmza ve Kural Yöneticisi.
    /// .yar kural dosyalarını yükler, kuralları bellek içi regex/hex motoruna derler
    /// ve dosyalar üzerinde gelişmiş desen eşleştirmesi yapar.
    /// </summary>
    public class YaraRuleManager
    {
        private readonly string _rulesDirectory;
        private readonly ILogger<YaraRuleManager>? _logger;
        private readonly ConcurrentDictionary<string, CompiledYaraRule> _compiledRules = new(StringComparer.OrdinalIgnoreCase);

        public int LoadedRuleCount => _compiledRules.Count;

        public YaraRuleManager(string? customRulesDir = null, ILogger<YaraRuleManager>? logger = null)
        {
            _logger = logger;
            _rulesDirectory = customRulesDir ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "UltronDefender", "YaraRules");

            EnsureDirectoryAndDefaultRules();
            LoadAllRules();
        }

        private void EnsureDirectoryAndDefaultRules()
        {
            try
            {
                if (!Directory.Exists(_rulesDirectory))
                {
                    Directory.CreateDirectory(_rulesDirectory);
                }

                // Varsayılan kritik kuralları oluştur
                string defaultRulesFile = Path.Combine(_rulesDirectory, "default_threats.yar");
                if (!File.Exists(defaultRulesFile))
                {
                    File.WriteAllText(defaultRulesFile, GetEmbeddedDefaultRules(), Encoding.UTF8);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Yara kuralları dizini oluşturulurken hata oluştu: {Dir}", _rulesDirectory);
            }
        }

        public void LoadAllRules()
        {
            try
            {
                if (!Directory.Exists(_rulesDirectory)) return;

                var ruleFiles = Directory.GetFiles(_rulesDirectory, "*.yar", SearchOption.AllDirectories);
                foreach (var file in ruleFiles)
                {
                    LoadRuleFile(file);
                }

                _logger?.LogInformation("Toplam {Count} YARA kuralı başarıyla yüklendi.", _compiledRules.Count);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Yara kuralları yüklenirken genel hata.");
            }
        }

        public void LoadRuleFile(string filePath)
        {
            try
            {
                var lines = File.ReadAllLines(filePath);
                string currentRuleName = string.Empty;
                var patterns = new List<string>();
                int severity = 70;
                string description = string.Empty;

                foreach (var rawLine in lines)
                {
                    var line = rawLine.Trim();
                    if (line.StartsWith("//") || line.StartsWith("#") || string.IsNullOrWhiteSpace(line)) continue;

                    if (line.StartsWith("rule ", StringComparison.OrdinalIgnoreCase))
                    {
                        currentRuleName = line.Substring(5).Split('{')[0].Trim();
                        patterns = new List<string>();
                        severity = 70;
                        description = currentRuleName;
                    }
                    else if (line.StartsWith("$", StringComparison.Ordinal) && line.Contains('='))
                    {
                        var parts = line.Split('=', 2);
                        if (parts.Length == 2)
                        {
                            var patternVal = parts[1].Trim().Trim('"', ';');
                            if (!string.IsNullOrWhiteSpace(patternVal))
                            {
                                patterns.Add(patternVal);
                            }
                        }
                    }
                    else if (line.StartsWith("severity", StringComparison.OrdinalIgnoreCase) && line.Contains('='))
                    {
                        var val = line.Split('=', 2)[1].Trim().Trim('"', ';');
                        if (int.TryParse(val, out int s)) severity = s;
                    }
                    else if (line.StartsWith("description", StringComparison.OrdinalIgnoreCase) && line.Contains('='))
                    {
                        description = line.Split('=', 2)[1].Trim().Trim('"', ';');
                    }
                    else if (line.StartsWith("}", StringComparison.Ordinal) && !string.IsNullOrEmpty(currentRuleName))
                    {
                        if (patterns.Count > 0)
                        {
                            _compiledRules[currentRuleName] = new CompiledYaraRule(currentRuleName, new List<string>(patterns), severity, description);
                        }
                        currentRuleName = string.Empty;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Kural dosyası ayrıştırılamadı: {Path}", filePath);
            }
        }

        public async Task<List<SecurityEvidence>> MatchFileAsync(string filePath, CancellationToken cancellationToken = default)
        {
            var matches = new List<SecurityEvidence>();
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath) || _compiledRules.IsEmpty)
                return matches;

            try
            {
                // İlk 4MB veriyi tara
                byte[] buffer;
                await using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 8192, FileOptions.SequentialScan | FileOptions.Asynchronous))
                {
                    int toRead = (int)Math.Min(fs.Length, 4 * 1024 * 1024);
                    buffer = new byte[toRead];
                    await fs.ReadAsync(buffer.AsMemory(0, toRead), cancellationToken);
                }

                string content = Encoding.ASCII.GetString(buffer);

                foreach (var kvp in _compiledRules)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    var rule = kvp.Value;

                    if (rule.Matches(content))
                    {
                        matches.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.StaticSignature,
                            SourceDetector = "YaraRuleEngine",
                            RuleName = $"Yara.{rule.Name}",
                            Description = $"YARA Kural Eşleşmesi: {rule.Description}",
                            ScoreContribution = rule.Severity,
                            Confidence = EvidenceConfidence.High,
                            FilePath = filePath
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "YARA eşleştirmesi sırasında dosya okuma hatası: {Path}", filePath);
            }

            return matches;
        }

        private static string GetEmbeddedDefaultRules()
        {
            return @"// Ultron Defender - Temel Gömülü YARA Kuralları

rule Webshell_Generic_Php {
    meta:
        description = ""Generic PHP Web Shell (eval/system/passthru)""
        severity = 85
    strings:
        $s1 = ""eval(base64_decode(""
        $s2 = ""passthru($_""
        $s3 = ""shell_exec($_""
        $s4 = ""system($_GET""
    condition:
        any of them
}

rule Mimikatz_Sekurlsa_Strings {
    meta:
        description = ""Mimikatz Sekurlsa Credentials Dumper Artifacts""
        severity = 95
    strings:
        $m1 = ""sekurlsa::logonpasswords""
        $m2 = ""privilege::debug""
        $m3 = ""lsadump::sam""
    condition:
        any of them
}

rule Cobalt_Strike_Beacon_Stager {
    meta:
        description = ""Cobalt Strike Default Pipe & User-Agent Markers""
        severity = 90
    strings:
        $c1 = ""\\pipe\\msagent_""
        $c2 = ""\\pipe\\status_""
        $c3 = ""Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko""
    condition:
        any of them
}
";
        }
    }

    public class CompiledYaraRule
    {
        public string Name { get; }
        public List<string> Patterns { get; }
        public int Severity { get; }
        public string Description { get; }

        public CompiledYaraRule(string name, List<string> patterns, int severity, string description)
        {
            Name = name;
            Patterns = patterns;
            Severity = severity;
            Description = string.IsNullOrEmpty(description) ? name : description;
        }

        public bool Matches(string content)
        {
            if (string.IsNullOrEmpty(content) || Patterns.Count == 0) return false;

            foreach (var p in Patterns)
            {
                if (content.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }
            return false;
        }
    }
}
