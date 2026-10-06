using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Security.Detection.YaraEngine;

namespace AegisPC.Security.Scanning;

/// <summary>Hashes and inspects bounded archive members without trusting their filename or extracting to disk.</summary>
internal static class ArchiveEntryInspector
{
    internal static async Task<(string Sha256, MalwareSignatureMatch Pattern, bool IsNestedContainer, List<YaraMatch> YaraMatches)> InspectAsync(
        ZipArchiveEntry entry, CancellationToken cancellationToken, IYaraEngine? yaraEngine = null)
    {
        const int chunkSize = 8192;
        const long maximumMemberBytes = 500L * 1024 * 1024;
        const int maximumRuleInputBytes = 10 * 1024 * 1024;
        if (entry.Length < 0 || entry.Length > maximumMemberBytes)
            throw new InvalidDataException("Archive member is outside the bounded inspection size.");
        int overlap = MalwareSignatureDatabase.ContentPatternOverlapBytes;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(chunkSize + overlap);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var stream = entry.Open();
            // Large members are hashed/stream-pattern checked without allocating their whole content.
            // Buffer-only rules remain explicitly bounded; the caller must report omitted rule/deep coverage.
            byte[]? ruleInput = yaraEngine != null && yaraEngine.LoadedRuleCount > 0 &&
                entry.Length < maximumRuleInputBytes ? new byte[checked((int)entry.Length)] : null;
            long actual = 0;
            int retained = 0;
            var best = new MalwareSignatureMatch();
            byte[] header = new byte[6];
            int headerLength = 0;
            byte[]? testContent = entry.Length <= 128 ? new byte[(int)entry.Length] : null;
            int read;
            while ((read = await stream.ReadAsync(buffer.AsMemory(retained, chunkSize), cancellationToken)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                actual = checked(actual + read);
                if (actual > entry.Length || actual > maximumMemberBytes)
                    throw new InvalidDataException("Archive member exceeds its declared length or inspection budget.");
                hash.AppendData(buffer, retained, read);
                if (testContent != null) Buffer.BlockCopy(buffer, retained, testContent, (int)actual - read, read);
                if (ruleInput != null) Buffer.BlockCopy(buffer, retained, ruleInput, checked((int)actual - read), read);
                int headerBytes = Math.Min(header.Length - headerLength, read);
                buffer.AsSpan(retained, headerBytes).CopyTo(header.AsSpan(headerLength));
                headerLength += headerBytes;
                int total = retained + read;
                var match = MalwareSignatureDatabase.CheckSpanPatterns(buffer.AsSpan(0, total));
                if (match.IsMatched && (!best.IsMatched || match.SeverityScore > best.SeverityScore)) best = match;
                retained = Math.Min(overlap, total);
                Buffer.BlockCopy(buffer, total - retained, buffer, 0, retained);
            }
            if (actual != entry.Length) throw new InvalidDataException("Archive member is truncated.");
            if (testContent != null)
            {
                var testMatch = MalwareSignatureDatabase.CheckCanonicalTestContent(testContent);
                if (testMatch.IsMatched) best = testMatch;
            }
            bool nested = HasContainerHeader(header.AsSpan(0, headerLength));
            var rules = ruleInput != null
                ? await yaraEngine!.ScanBufferAsync(ruleInput, entry.FullName, cancellationToken)
                : new List<YaraMatch>();
            cancellationToken.ThrowIfCancellationRequested();
            return (Convert.ToHexString(hash.GetHashAndReset()), best, nested, rules);
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }

    internal static bool HasContainerHeader(ReadOnlySpan<byte> header) =>
        (header.Length >= 2 && header[0] == 0x50 && header[1] == 0x4b) ||
        (header.Length >= 2 && header[0] == 0x1f && header[1] == 0x8b) ||
        header.StartsWith("Rar!"u8) || header.StartsWith("BZh"u8) || header.StartsWith("MSCF"u8) ||
        header.StartsWith(new byte[] { 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c }) ||
        header.StartsWith(new byte[] { 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00 });
}
