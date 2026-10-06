using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection.YaraEngine;

namespace AegisPC.Security.Scanning;

/// <summary>Provides bounded, one-level nested ZIP inspection while preserving incomplete-coverage status.</summary>
public partial class ArchiveSafetyScanner
{
    private sealed class NestedArchiveInspectionBudget
    {
        internal int Archives;
        internal int Entries;
        internal long ExpandedBytes;
    }

    private async Task InspectNestedZipAsync(ZipArchiveEntry source, string outerPath, ArchiveScanResult result,
        NestedArchiveInspectionBudget budget, CancellationToken cancellationToken)
    {
        const int maxNestedArchives = 8;
        const int maxNestedEntries = 256;
        const long maxNestedExpandedBytes = 32L * 1024 * 1024;
        if (budget.Archives >= maxNestedArchives)
        {
            result.CoverageLimitation = "İç içe ZIP/JAR sayısı bütçesi aşıldı.";
            return;
        }

        // The caller already verified this member is smaller than the 10 MiB inspection limit.
        using var nestedBytes = new MemoryStream(checked((int)source.Length));
        using (var sourceStream = source.Open())
        {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = await sourceStream.ReadAsync(buffer, cancellationToken)) > 0)
            {
                if (nestedBytes.Length + read > source.Length)
                    throw new InvalidDataException("Nested archive exceeded its declared member length.");
                await nestedBytes.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
        }
        if (nestedBytes.Length != source.Length)
            throw new InvalidDataException("Nested archive member was truncated.");
        nestedBytes.Position = 0;
        if (nestedBytes.Length < 2 || nestedBytes.ReadByte() != 0x50 || nestedBytes.ReadByte() != 0x4b)
            return; // Other container formats remain explicitly partial.
        nestedBytes.Position = 0;
        budget.Archives++;
        using var nestedArchive = new ZipArchive(nestedBytes, ZipArchiveMode.Read, leaveOpen: true);
        foreach (var member in nestedArchive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (++budget.Entries > maxNestedEntries)
            {
                result.CoverageLimitation = "İç içe ZIP/JAR üye sayısı bütçesi aşıldı.";
                break;
            }
            if (member.Length < 0 || member.Length >= 10 * 1024 * 1024 ||
                budget.ExpandedBytes + member.Length > maxNestedExpandedBytes)
            {
                result.CoverageLimitation = "İç içe ZIP/JAR açılmış boyut bütçesi aşıldı.";
                break;
            }
            budget.ExpandedBytes += member.Length;
            result.TotalEntries++;
            result.TotalUncompressedBytes += member.Length;
            if (member.Length == 0) continue;
            await InspectNestedMemberAsync(member, outerPath, source.FullName, result, cancellationToken);
            if (result.Findings.Count >= 512)
            {
                result.CoverageLimitation = "Arşiv bulgu sayısı sınırı aşıldı; kalan içerik incelenemedi.";
                break;
            }
        }
    }

    private async Task InspectNestedMemberAsync(ZipArchiveEntry member, string outerPath, string parentName,
        ArchiveScanResult result, CancellationToken cancellationToken)
    {
        IYaraEngine? rules = _yaraEngine;
        if (rules != null && (rules.LoadedRuleCount == 0 ||
            (rules.MaximumScanBytes.HasValue && member.Length > rules.MaximumScanBytes.Value)))
        {
            result.CoverageLimitation = "İç içe üyenin YARA incelemesi kullanılamıyor veya bütçeyi aşıyor.";
            rules = null;
        }
        var (sha256, pattern, deeperContainer, yaraMatches) =
            await ArchiveEntryInspector.InspectAsync(member, cancellationToken, rules);
        result.HashedMembers++;
        result.HashedExpandedBytes = checked(result.HashedExpandedBytes + member.Length);
        if (result.MemberHashes.Count < 256)
        {
            var memberName = $"{parentName} -> {member.FullName}";
            result.MemberHashes.Add(new(memberName[..Math.Min(memberName.Length, 512)], sha256, member.Length));
        }
        if (deeperContainer)
            result.CoverageLimitation = "İki seviyeden derin arşiv içeriği incelenmedi.";

        var known = MalwareSignatureDatabase.CheckHash(sha256);
        if (known.IsMatched || pattern.IsMatched)
        {
            // Mutable disk signatures can flag a candidate but cannot establish a
            // confirmed risk tier for a nested member without independent verification.
            bool confirmed = MalwareSignatureDatabase.IsTrustedEmbeddedHash(sha256);
            var match = known.IsMatched ? known : pattern;
            result.Findings.Add(new SecurityFinding
            {
                ObjectPath = $"{outerPath} -> {parentName} -> {member.FullName}",
                ObjectName = member.Name,
                SHA256 = sha256,
                Category = confirmed ? FindingCategory.KnownMalwareHash : FindingCategory.SuspiciousScript,
                RiskLevel = confirmed ? RiskLevel.ConfirmedMalicious : RiskLevel.Suspicious,
                RiskScore = confirmed ? match.SeverityScore : Math.Min(65, match.SeverityScore),
                Title = $"İç İçe Arşivde Tehdit: {match.ThreatName}",
                Description = "İç içe ZIP/JAR üyesinin içerik imzası eşleşti; tüm kapsayıcı kapsamı hâlâ kısmi.",
                ConfidenceLevel = ConfidenceLevel.High
            });
        }
        int ruleBudget = Math.Max(0, 512 - result.Findings.Count);
        foreach (var rule in yaraMatches.Take(ruleBudget))
        {
            result.Findings.Add(new SecurityFinding
            {
                ObjectPath = $"{outerPath} -> {parentName} -> {member.FullName}",
                ObjectName = member.Name,
                SHA256 = sha256,
                Category = FindingCategory.MalwareSuspicion,
                RiskLevel = RiskLevel.Suspicious,
                RiskScore = Math.Clamp(rule.Severity > 0 ? rule.Severity : 65, 1, 75),
                Title = $"İç İçe Arşiv Üyesinde YARA Kuralı: {rule.RuleName}",
                Description = "İç içe arşiv üyesinde yapılandırılmış YARA kuralı eşleşti; tek başına doğrulanmış zararlı değildir.",
                ConfidenceLevel = ConfidenceLevel.Medium
            });
        }
        if (yaraMatches.Count > ruleBudget)
            result.CoverageLimitation = "İç içe arşiv YARA bulguları çıktı sınırına ulaştı.";
    }
}
