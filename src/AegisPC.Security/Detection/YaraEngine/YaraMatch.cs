using System;
using System.Collections.Generic;

namespace AegisPC.Security.Detection.YaraEngine
{
    /// <summary>
    /// Eşleşen YARA string veya byte deseni ve dosya ofseti.
    /// </summary>
    public class YaraStringMatch
    {
        public string Identifier { get; set; } = string.Empty;
        public long Offset { get; set; }
        public string MatchedValue { get; set; } = string.Empty;

        public override string ToString() => $"{Identifier} at 0x{Offset:X8}";
    }

    /// <summary>
    /// Bir YARA kuralı eşleşme sonucu, metaverisi ve ofset ayrıntıları.
    /// </summary>
    public class YaraMatch
    {
        public string RuleName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int Severity { get; set; } = 100;
        public List<string> Tags { get; set; } = new();
        public Dictionary<string, string> Metadata { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<YaraStringMatch> MatchedStrings { get; set; } = new();

        public override string ToString() => $"[YARA Match] {RuleName} (Sev: {Severity}, Matches: {MatchedStrings.Count})";
    }

    /// <summary>
    /// YARA Kural Motoru Arayüzü.
    /// </summary>
    public interface IYaraEngine
    {
        int LoadedRuleCount { get; }
        string RulesDirectory { get; }
        void ReloadRules();
        System.Threading.Tasks.Task<List<YaraMatch>> ScanFileAsync(string filePath, System.Threading.CancellationToken ct = default);
        System.Threading.Tasks.Task<List<YaraMatch>> ScanBufferAsync(byte[] buffer, string identifier = "", System.Threading.CancellationToken ct = default);
    }
}
