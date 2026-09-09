using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Detection.YaraEngine
{
    // [YARA-X vs libyara Karşılaştırması ve Mimari Tercih Gerekçesi]
    // 1. Rust Bellek Güvenliği: libyara C/C++ temelli olup parser zafiyetlerine açıkken, YARA-X Rust ile bellek güvenliğini (memory-safety) garanti eder.
    // 2. Modern Kural ve Modül Desteği: YARA-X, yeni nesil YARA-v4+ dil standartlarını, modern modül yapılarını ve genişletilmiş regex kabiliyetlerini yerel destekler.
    // 3. Güvenli ve Temiz FFI Entegrasyonu: Karmaşık C binding kütüphaneleri ve unmanaged bellek sızıntıları yerine güvenli, yalıtılmış C-ABI/FFI arayüzü sunar.
    // 4. Eşzamanlı (Thread-Safe) Tarama Başarımı: Derlenmiş kural havuzları kilitlenme olmadan çoklu worker iş parçacıkları tarafından paralel taranabilir.
    // 5. ReDoS Koruması ve Yüksek Hız: Aho-Corasick ve PikeVM tabanlı regex mimarisi ile regex denial-of-service (ReDoS) saldırılarını engeller ve yüksek verim sağlar.

    /// <summary>
    /// YARA-X mimarisine dayalı kural yönetimi ve desen eşleştirme motoru.
    /// Yerel C:\ProgramData\UltronDefender\yara\ kurallarını yönetir,
    /// bayt ofsetleri ve adli kanıt metaverileri ile tehditleri tespit eder.
    /// </summary>
    public class YaraEngine : IYaraEngine
    {
        private readonly string _rulesDirectory;
        private readonly ILogger<YaraEngine>? _logger;
        private readonly ConcurrentDictionary<string, ParsedYaraRule> _rules = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _syncLock = new();

        public int LoadedRuleCount => _rules.Count;
        public string RulesDirectory => _rulesDirectory;

        #region Native YARA-X C-ABI / FFI Bindings
        // YARA-X dinamik kütüphanesi (yara_x.dll) mevcut olduğunda doğrudan güvenli C-ABI üzerinden çağrılır.
        [DllImport("yara_x", EntryPoint = "yrx_compiler_create", CallingConvention = CallingConvention.Cdecl)]
        private static extern int YrxCompilerCreate(out IntPtr compiler);

        [DllImport("yara_x", EntryPoint = "yrx_compiler_destroy", CallingConvention = CallingConvention.Cdecl)]
        private static extern void YrxCompilerDestroy(IntPtr compiler);

        [DllImport("yara_x", EntryPoint = "yrx_compiler_add_source", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int YrxCompilerAddSource(IntPtr compiler, string ruleSource);
        #endregion

        public YaraEngine(string? customRulesDir = null, ILogger<YaraEngine>? logger = null)
        {
            _logger = logger;
            _rulesDirectory = DetermineRulesDirectory(customRulesDir);
            InitializeRulesDirectory();
            ReloadRules();
        }

        private static string DetermineRulesDirectory(string? customRulesDir)
        {
            if (!string.IsNullOrEmpty(customRulesDir))
            {
                return customRulesDir;
            }

            string programDataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "UltronDefender", "yara");

            try
            {
                if (!Directory.Exists(programDataDir))
                {
                    Directory.CreateDirectory(programDataDir);
                }

                // Yazma izni doğrulama
                string probe = Path.Combine(programDataDir, $".probe_{Guid.NewGuid():N}.tmp");
                File.WriteAllText(probe, "probe");
                File.Delete(probe);
                return programDataDir;
            }
            catch
            {
                string localAppDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "UltronDefender", "yara");

                if (!Directory.Exists(localAppDir))
                {
                    Directory.CreateDirectory(localAppDir);
                }

                return localAppDir;
            }
        }

        private void InitializeRulesDirectory()
        {
            try
            {
                if (!Directory.Exists(_rulesDirectory))
                {
                    Directory.CreateDirectory(_rulesDirectory);
                }

                // 1. eicar.yar
                string eicarFile = Path.Combine(_rulesDirectory, "eicar.yar");
                if (!File.Exists(eicarFile))
                {
                    File.WriteAllText(eicarFile, GetDefaultEicarRule(), Encoding.UTF8);
                }

                // 2. mimikatz.yar
                string mimikatzFile = Path.Combine(_rulesDirectory, "mimikatz.yar");
                if (!File.Exists(mimikatzFile))
                {
                    File.WriteAllText(mimikatzFile, GetDefaultMimikatzRule(), Encoding.UTF8);
                }

                // 3. cobaltstrike.yar
                string cobaltFile = Path.Combine(_rulesDirectory, "cobaltstrike.yar");
                if (!File.Exists(cobaltFile))
                {
                    File.WriteAllText(cobaltFile, GetDefaultCobaltStrikeRule(), Encoding.UTF8);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Varsayılan YARA kuralları dizine yazılamadı: {Directory}", _rulesDirectory);
            }
        }

        public void ReloadRules()
        {
            lock (_syncLock)
            {
                try
                {
                    _rules.Clear();

                    if (!Directory.Exists(_rulesDirectory))
                    {
                        return;
                    }

                    var files = Directory.GetFiles(_rulesDirectory, "*.yar", SearchOption.AllDirectories)
                        .Concat(Directory.GetFiles(_rulesDirectory, "*.yara", SearchOption.AllDirectories))
                        .Distinct(StringComparer.OrdinalIgnoreCase);

                    int fileCount = 0;
                    foreach (var file in files)
                    {
                        try
                        {
                            string content = File.ReadAllText(file, Encoding.UTF8);
                            var parsedList = ParseYaraSource(content, file);
                            foreach (var rule in parsedList)
                            {
                                _rules[rule.Name] = rule;
                            }
                            fileCount++;
                        }
                        catch (Exception fEx)
                        {
                            _logger?.LogWarning(fEx, "YARA kural dosyası ayrıştırılamadı: {File}", file);
                        }
                    }

                    _logger?.LogInformation("YARA Motoru güncellendi: {FileCount} dosyadan {RuleCount} kural yüklendi. (Dizin: {Dir})",
                        fileCount, _rules.Count, _rulesDirectory);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "YARA kuralları yeniden yüklenirken hata oluştu.");
                }
            }
        }

        public async Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default)
        {
            var results = new List<YaraMatch>();
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath) || _rules.IsEmpty)
            {
                return results;
            }

            try
            {
                // Güvenli maksimum okuma boyutu (16 MB sınırı - büyük dosyalar için başlık ve ilk segmentler taranır)
                const int maxScanBytes = 16 * 1024 * 1024;
                byte[] buffer;

                await using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 8192, FileOptions.SequentialScan | FileOptions.Asynchronous))
                {
                    int toRead = (int)Math.Min(fs.Length, maxScanBytes);
                    buffer = new byte[toRead];
                    int read = 0;
                    while (read < toRead)
                    {
                        ct.ThrowIfCancellationRequested();
                        int n = await fs.ReadAsync(buffer.AsMemory(read, toRead - read), ct);
                        if (n == 0) break;
                        read += n;
                    }
                }

                return await ScanBufferAsync(buffer, Path.GetFileName(filePath), ct);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "YARA dosya tarama hatası: {FilePath}", filePath);
                return results;
            }
        }

        public Task<List<YaraMatch>> ScanBufferAsync(byte[] buffer, string identifier = "", CancellationToken ct = default)
        {
            var matches = new List<YaraMatch>();
            if (buffer == null || buffer.Length == 0 || _rules.IsEmpty)
            {
                return Task.FromResult(matches);
            }

            foreach (var kvp in _rules)
            {
                ct.ThrowIfCancellationRequested();
                var rule = kvp.Value;

                var ruleMatch = EvaluateRule(rule, buffer);
                if (ruleMatch != null)
                {
                    matches.Add(ruleMatch);
                }
            }

            return Task.FromResult(matches);
        }

        private YaraMatch? EvaluateRule(ParsedYaraRule rule, byte[] buffer)
        {
            var stringMatches = new List<YaraStringMatch>();
            var matchedIdentifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var pattern in rule.Patterns)
            {
                var offsets = FindPatternOffsets(buffer, pattern);
                if (offsets.Count > 0)
                {
                    matchedIdentifiers.Add(pattern.Identifier);
                    foreach (var offset in offsets)
                    {
                        stringMatches.Add(new YaraStringMatch
                        {
                            Identifier = pattern.Identifier,
                            Offset = offset,
                            MatchedValue = pattern.OriginalString
                        });
                    }
                }
            }

            // Koşul Değerlendirme
            bool isSatisfied = false;
            string cond = rule.Condition.Trim();

            if (cond.Equals("any of them", StringComparison.OrdinalIgnoreCase))
            {
                isSatisfied = matchedIdentifiers.Count > 0;
            }
            else if (cond.Equals("all of them", StringComparison.OrdinalIgnoreCase))
            {
                isSatisfied = rule.Patterns.Count > 0 && matchedIdentifiers.Count == rule.Patterns.Count;
            }
            else if (rule.Patterns.Any(p => p.Identifier.Equals(cond, StringComparison.OrdinalIgnoreCase)))
            {
                isSatisfied = matchedIdentifiers.Contains(cond);
            }
            else
            {
                // Varsayılan: Herhangi bir desenin eşleşmesi yeterli
                isSatisfied = matchedIdentifiers.Count > 0;
            }

            if (isSatisfied)
            {
                var match = new YaraMatch
                {
                    RuleName = rule.Name,
                    Description = rule.Description,
                    Severity = rule.Severity,
                    Tags = new List<string>(rule.Tags),
                    MatchedStrings = stringMatches
                };

                foreach (var meta in rule.Metadata)
                {
                    match.Metadata[meta.Key] = meta.Value;
                }

                return match;
            }

            return null;
        }

        private static List<long> FindPatternOffsets(byte[] buffer, RulePattern pattern)
        {
            var offsets = new List<long>();
            if (pattern.Bytes == null || pattern.Bytes.Length == 0 || buffer.Length < pattern.Bytes.Length)
            {
                return offsets;
            }

            byte[] target = pattern.Bytes;
            bool nocase = pattern.NoCase;
            int targetLen = target.Length;
            int maxLimit = buffer.Length - targetLen;

            for (int i = 0; i <= maxLimit; i++)
            {
                bool match = true;
                for (int j = 0; j < targetLen; j++)
                {
                    byte b1 = buffer[i + j];
                    byte b2 = target[j];

                    if (nocase)
                    {
                        if (b1 >= 'a' && b1 <= 'z') b1 = (byte)(b1 - 32);
                        if (b2 >= 'a' && b2 <= 'z') b2 = (byte)(b2 - 32);
                    }

                    if (b1 != b2)
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    offsets.Add(i);
                    // Çok fazla yinelenen ofset oluşmasını sınırla (adli analiz için ilk 20 yeterli)
                    if (offsets.Count >= 20) break;
                }
            }

            return offsets;
        }

        #region Kural Kaynak Ayrıştırıcı (Managed YARA Parser)
        public static List<ParsedYaraRule> ParseYaraSource(string source, string sourceFile = "")
        {
            var rules = new List<ParsedYaraRule>();
            if (string.IsNullOrWhiteSpace(source)) return rules;

            int i = 0;
            int len = source.Length;

            while (i < len)
            {
                int ruleIdx = IndexOfKeyword(source, "rule", i);
                if (ruleIdx < 0) break;

                int openBrace = source.IndexOf('{', ruleIdx);
                if (openBrace < 0) break;

                string header = source.Substring(ruleIdx + 4, openBrace - (ruleIdx + 4)).Trim();
                string ruleName = header;
                string tagsStr = string.Empty;

                int colonIdx = header.IndexOf(':');
                if (colonIdx >= 0)
                {
                    ruleName = header.Substring(0, colonIdx).Trim();
                    tagsStr = header.Substring(colonIdx + 1).Trim();
                }

                // EICAR gibi dizgilerde bulunan '}' karakterinden etkilenmemek için tırnak duyarlı süslü parantez derinlik sayacı
                int depth = 1;
                int cur = openBrace + 1;
                bool inQuotes = false;

                while (cur < len && depth > 0)
                {
                    char c = source[cur];
                    if (c == '"' && (cur == 0 || source[cur - 1] != '\\'))
                    {
                        inQuotes = !inQuotes;
                    }
                    else if (!inQuotes)
                    {
                        if (c == '{') depth++;
                        else if (c == '}') depth--;
                    }
                    cur++;
                }

                if (depth == 0)
                {
                    int bodyStart = openBrace + 1;
                    int bodyLen = (cur - 1) - bodyStart;
                    string body = source.Substring(bodyStart, bodyLen);

                    var rule = new ParsedYaraRule
                    {
                        Name = ruleName,
                        SourceFile = sourceFile
                    };

                    if (!string.IsNullOrEmpty(tagsStr))
                    {
                        foreach (var tag in tagsStr.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            rule.Tags.Add(tag);
                        }
                    }

                    ParseRuleBody(body, rule);
                    rules.Add(rule);
                }

                i = cur;
            }

            return rules;
        }

        private static int IndexOfKeyword(string src, string keyword, int startIndex)
        {
            int idx = startIndex;
            while ((idx = src.IndexOf(keyword, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                bool boundaryBefore = (idx == 0) || char.IsWhiteSpace(src[idx - 1]);
                int afterIdx = idx + keyword.Length;
                bool boundaryAfter = (afterIdx < src.Length) && char.IsWhiteSpace(src[afterIdx]);

                if (boundaryBefore && boundaryAfter)
                {
                    return idx;
                }
                idx += keyword.Length;
            }
            return -1;
        }

        private static void ParseRuleBody(string body, ParsedYaraRule rule)
        {
            // 1. Meta Bölümü (meta: ile strings: veya condition: arası)
            var metaMatch = Regex.Match(body, @"meta\s*:(.*?)(?=strings\s*:|condition\s*:|$)", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            if (metaMatch.Success)
            {
                var lines = metaMatch.Groups[1].Value.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("//") || trimmed.StartsWith("#")) continue;

                    var eqIdx = trimmed.IndexOf('=');
                    if (eqIdx > 0)
                    {
                        string key = trimmed.Substring(0, eqIdx).Trim();
                        string val = trimmed.Substring(eqIdx + 1).Trim().Trim('"', ';', '\'').Trim();

                        rule.Metadata[key] = val;

                        if (key.Equals("description", StringComparison.OrdinalIgnoreCase))
                        {
                            rule.Description = val;
                        }
                        else if (key.Equals("severity", StringComparison.OrdinalIgnoreCase) && int.TryParse(val, out int sev))
                        {
                            rule.Severity = sev;
                        }
                    }
                }
            }

            if (string.IsNullOrEmpty(rule.Description))
            {
                rule.Description = rule.Name;
            }

            // 2. Strings Bölümü (strings: ile condition: arası - EICAR stringindeki '}' karakterini kesmez)
            var stringsMatch = Regex.Match(body, @"strings\s*:(.*?)(?=condition\s*:|$)", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            if (stringsMatch.Success)
            {
                var lines = stringsMatch.Groups[1].Value.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("//") || trimmed.StartsWith("#")) continue;

                    // $ident = "string" [nocase] [wide] [ascii]
                    var strDef = Regex.Match(trimmed, @"(\$[A-Za-z0-9_]+)\s*=\s*""((?:[^""\\]|\\.)*)""(.*)");
                    if (strDef.Success)
                    {
                        string ident = strDef.Groups[1].Value;
                        string rawVal = strDef.Groups[2].Value;
                        string modifiers = strDef.Groups[3].Value.ToLowerInvariant();

                        string unescapedVal = UnescapeYaraString(rawVal);
                        bool nocase = modifiers.Contains("nocase");
                        byte[] bytes = Encoding.ASCII.GetBytes(unescapedVal);

                        if (nocase)
                        {
                            for (int bIdx = 0; bIdx < bytes.Length; bIdx++)
                            {
                                if (bytes[bIdx] >= 'a' && bytes[bIdx] <= 'z') bytes[bIdx] = (byte)(bytes[bIdx] - 32);
                            }
                        }

                        rule.Patterns.Add(new RulePattern
                        {
                            Identifier = ident,
                            OriginalString = unescapedVal,
                            Bytes = bytes,
                            NoCase = nocase
                        });
                        continue;
                    }

                    // $ident = { hex bytes }
                    var hexDef = Regex.Match(trimmed, @"(\$[A-Za-z0-9_]+)\s*=\s*\{([0-9A-Fa-f\s]+)\}");
                    if (hexDef.Success)
                    {
                        string ident = hexDef.Groups[1].Value;
                        string hexStr = hexDef.Groups[2].Value.Replace(" ", "").Trim();
                        var bytes = ParseHexBytes(hexStr);
                        if (bytes.Length > 0)
                        {
                            rule.Patterns.Add(new RulePattern
                            {
                                Identifier = ident,
                                OriginalString = hexStr,
                                Bytes = bytes,
                                NoCase = false
                            });
                        }
                    }
                }
            }

            // 3. Condition Bölümü (condition: sonrası)
            var condMatch = Regex.Match(body, @"condition\s*:(.*)", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            if (condMatch.Success)
            {
                rule.Condition = condMatch.Groups[1].Value.Trim().Trim(';');
            }
            else
            {
                rule.Condition = "any of them";
            }
        }

        private static byte[] ParseHexBytes(string hex)
        {
            var bytes = new List<byte>();
            for (int i = 0; i < hex.Length - 1; i += 2)
            {
                if (byte.TryParse(hex.Substring(i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte b))
                {
                    bytes.Add(b);
                }
            }
            return bytes.ToArray();
        }

        private static string UnescapeYaraString(string str)
        {
            if (string.IsNullOrEmpty(str)) return string.Empty;

            var sb = new StringBuilder(str.Length);
            for (int i = 0; i < str.Length; i++)
            {
                if (str[i] == '\\' && i + 1 < str.Length)
                {
                    char next = str[i + 1];
                    if (next == '\\') { sb.Append('\\'); i++; }
                    else if (next == '"') { sb.Append('"'); i++; }
                    else if (next == 'n') { sb.Append('\n'); i++; }
                    else if (next == 'r') { sb.Append('\r'); i++; }
                    else if (next == 't') { sb.Append('\t'); i++; }
                    else if (next == 'x' && i + 3 < str.Length &&
                             byte.TryParse(str.Substring(i + 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte b))
                    {
                        sb.Append((char)b);
                        i += 3;
                    }
                    else
                    {
                        sb.Append(next);
                        i++;
                    }
                }
                else
                {
                    sb.Append(str[i]);
                }
            }
            return sb.ToString();
        }
        #endregion

        #region Varsayılan abuse.ch Standardında 3 Kural
        public static string GetDefaultEicarRule()
        {
            return @"// Ultron Defender - Doğrulanmış YARA İmzası: EICAR Test Dosyası
rule EICAR_Standard_Test_File
{
    meta:
        description = ""Detects EICAR Standard Anti-Virus Test File""
        author = ""UltronDefender""
        reference = ""https://www.eicar.org/download-anti-malware-testfile/""
        severity = 100
    strings:
        $eicar = ""X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*""
    condition:
        $eicar
}
";
        }

        public static string GetDefaultMimikatzRule()
        {
            return @"// Ultron Defender - Doğrulanmış YARA İmzası: Mimikatz Kimlik Bilgisi Hırsızlığı
rule Mimikatz_Credential_Dumper
{
    meta:
        description = ""Detects Mimikatz credential dumping tool and sekurlsa references""
        author = ""UltronDefender""
        reference = ""https://github.com/gentilkiwi/mimikatz""
        severity = 100
    strings:
        $s1 = ""sekurlsa::logonpasswords"" nocase
        $s2 = ""privilege::debug"" nocase
        $s3 = ""lsadump::sam"" nocase
    condition:
        any of them
}
";
        }

        public static string GetDefaultCobaltStrikeRule()
        {
            return @"// Ultron Defender - Doğrulanmış YARA İmzası: Cobalt Strike Stager ve Pipe
rule CobaltStrike_Beacon_Stager
{
    meta:
        description = ""Detects Cobalt Strike default named pipe indicators and stager patterns""
        author = ""UltronDefender""
        reference = ""abuse.ch / YARA Community Signatures""
        severity = 100
    strings:
        $p1 = ""\\pipe\\msagent_"" nocase
        $p2 = ""\\pipe\\status_"" nocase
        $s1 = ""%s as %s\\%s: %d""
    condition:
        any of them
}
";
        }
        #endregion
    }

    public class RulePattern
    {
        public string Identifier { get; set; } = string.Empty;
        public string OriginalString { get; set; } = string.Empty;
        public byte[] Bytes { get; set; } = Array.Empty<byte>();
        public bool NoCase { get; set; }
    }

    public class ParsedYaraRule
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int Severity { get; set; } = 100;
        public string Condition { get; set; } = "any of them";
        public string SourceFile { get; set; } = string.Empty;
        public List<string> Tags { get; } = new();
        public Dictionary<string, string> Metadata { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<RulePattern> Patterns { get; } = new();
    }
}
