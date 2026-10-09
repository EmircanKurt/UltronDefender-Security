using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>
/// Identifies formats from bounded structural reads. It never executes, extracts, follows shortcut targets,
/// or interprets an extension mismatch as malware. Source locks are owned by the calling scan session.
/// </summary>
public sealed class FileContentClassifier : IFileContentClassifier
{
    internal const int PrefixBudget = 128 * 1024;
    internal const int TailBudget = 65557;

    /// <summary>
    /// Classifies a readable seekable source with a 128 KiB prefix, a bounded end-record sample and at most
    /// 1 MiB of ZIP directory metadata. Restores the original position on success, failure or cancellation.
    /// </summary>
    public async Task<FileContentClassification> ClassifyAsync(Stream source, string declaredExtension, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!source.CanRead || !source.CanSeek) throw new ArgumentException("Content classification requires a readable seekable source.", nameof(source));
        cancellationToken.ThrowIfCancellationRequested();
        using var contentMeasurement = ScanStageMeasurements.Measure(ScanStageTiming.Content);
        var result = new FileContentClassification { DeclaredExtension = (declaredExtension ?? string.Empty).ToLowerInvariant() };
        long original = source.Position;
        try
        {
            var prefix = await ReadAtAsync(source, 0, (int)Math.Min(PrefixBudget, source.Length), cancellationToken);
            long tailOffset = Math.Max(0, source.Length - TailBudget);
            var tail = tailOffset == 0 ? prefix.Length == source.Length ? prefix : await ReadAtAsync(source, 0, (int)source.Length, cancellationToken)
                : await ReadAtAsync(source, tailOffset, (int)(source.Length - tailOffset), cancellationToken);
            ContentStructureValidator.InspectPrefix(prefix, tail, source.Length, result);
            await ZipContentStructureInspector.InspectAsync(source, prefix, tail, tailOffset, result, cancellationToken);
            if (result.Formats.Count == 0) IdentifyText(prefix, source.Length, result);
            Finish(result);
            return result;
        }
        finally { source.Position = original; }
    }

    internal static async Task<byte[]> ReadAtAsync(Stream source, long offset, int count, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (offset < 0 || count < 0 || offset > source.Length || count > source.Length - offset)
            throw new InvalidDataException("Structure points outside the source file.");
        source.Position = offset;
        var data = new byte[count];
        await source.ReadExactlyAsync(data.AsMemory(), ct);
        return data;
    }

    internal static void Limit(FileContentClassification result, string message, ContentClassificationCoverage coverage = ContentClassificationCoverage.Partial)
    {
        result.Coverage = coverage;
        if (!result.CoverageLimitations.Contains(message, StringComparer.Ordinal)) result.CoverageLimitations.Add(message);
    }

    private static void IdentifyText(byte[] prefix, long length, FileContentClassification result)
    {
        if (prefix.Length == 0) return;
        string text;
        try
        {
            // A strict decoder avoids classifying random binary bytes as replacement-character text.
            bool utf16 = prefix.Length >= 2 && ((prefix[0] == 0xff && prefix[1] == 0xfe) || (prefix[0] == 0xfe && prefix[1] == 0xff));
            Encoding encoding = utf16 ? new UnicodeEncoding(prefix[0] == 0xfe, true, true) : new UTF8Encoding(false, true);
            int sampled = prefix.Length;
            if (utf16 && sampled % 2 != 0) sampled--;
            text = encoding.GetString(prefix, utf16 ? 2 : 0, sampled - (utf16 ? 2 : 0));
        }
        catch (DecoderFallbackException)
        {
            result.Observations.Add("Sample is not strict UTF-8 or BOM-marked UTF-16 text.");
            return;
        }
        if (text.Any(c => char.IsControl(c) && c is not '\r' and not '\n' and not '\t' and not '\f')) return;
        result.Formats.Add(FileContentFormat.Text);
        string start = text.TrimStart('\ufeff', ' ', '\t', '\r', '\n');
        if (start.StartsWith("#!", StringComparison.Ordinal) || start.StartsWith("@echo", StringComparison.OrdinalIgnoreCase) ||
            start.StartsWith("param(", StringComparison.OrdinalIgnoreCase) || start.StartsWith("<?php", StringComparison.OrdinalIgnoreCase) ||
            start.StartsWith("<script", StringComparison.OrdinalIgnoreCase))
            result.Formats.Add(FileContentFormat.ScriptCandidate);
        result.Observations.Add("Text/sample classification is a detector routing hint, not a trust decision.");
        if (length > prefix.Length) Limit(result, "Only a bounded text prefix was classified; the remainder is not identified.");
    }

    private static void Finish(FileContentClassification result)
    {
        if (result.Formats.Count == 0)
        {
            result.Formats.Add(FileContentFormat.Unknown);
            Limit(result, "No supported structure was established from the bounded source reads.", ContentClassificationCoverage.Unknown);
        }
        int independent = result.Formats.Count(f => f is FileContentFormat.PortableExecutable or FileContentFormat.Zip or FileContentFormat.Pdf or
            FileContentFormat.Png or FileContentFormat.Jpeg or FileContentFormat.WindowsShortcut);
        result.IsAmbiguous = independent > 1;
        if (result.IsAmbiguous) result.Observations.Add("Multiple top-level structures observed; all applicable detectors must run.");
        var expected = result.DeclaredExtension switch
        {
            ".exe" or ".dll" or ".sys" or ".scr" or ".cpl" or ".ocx" or ".efi" => FileContentFormat.PortableExecutable,
            ".zip" or ".jar" or ".docx" or ".xlsx" or ".pptx" or ".docm" or ".xlsm" or ".pptm" => FileContentFormat.Zip,
            ".pdf" => FileContentFormat.Pdf,
            ".png" => FileContentFormat.Png,
            ".jpg" or ".jpeg" => FileContentFormat.Jpeg,
            ".lnk" => FileContentFormat.WindowsShortcut,
            _ => FileContentFormat.Unknown
        };
        result.HasExtensionMismatch = expected != FileContentFormat.Unknown && !result.Formats.Contains(expected);
        if (result.HasExtensionMismatch) result.Observations.Add("Declared extension does not match the observed supported structures.");
    }
}
