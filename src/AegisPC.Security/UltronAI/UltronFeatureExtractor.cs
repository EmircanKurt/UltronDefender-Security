using System.Security.Cryptography;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using PeNet;

namespace AegisPC.Security.UltronAI;

/// <summary>Extracts bounded static features from one locked source; imports are not executed behavior.</summary>
public static class UltronFeatureExtractor
{
    private const int MaximumPeBytes = 4 * 1024 * 1024;
    private const int EntropySampleBytes = 1024 * 1024;
    private static readonly HashSet<string> Packers = new(StringComparer.OrdinalIgnoreCase)
        { "UPX0", "UPX1", "UPX2", ".aspack", ".mpress", ".themida", ".vmp", "vmp0", "vmp1", ".enigma" };
    private static readonly HashSet<string> MemoryApis = new(StringComparer.OrdinalIgnoreCase)
        { "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC" };
    private static readonly HashSet<string> InjectionApis = new(StringComparer.OrdinalIgnoreCase)
        { "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "ResumeThread" };
    private static readonly HashSet<string> DebugApis = new(StringComparer.OrdinalIgnoreCase)
        { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess" };

    /// <summary>Compatibility entry point with one read-only lock and explicit input failure.</summary>
    public static UltronFeatureVector Extract(string filePath)
    {
        try
        {
            using var source = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var classification = new FileContentClassifier().ClassifyAsync(source, Path.GetExtension(filePath)).GetAwaiter().GetResult();
            return Extract(source, filePath, classification);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { return new() { TargetPath = filePath, CoverageLimitations = new() { "InputUnavailable" } }; }
    }

    /// <summary>Preserves caller position and does not own/dispose the shared stream. No location or extension exemptions.</summary>
    public static UltronFeatureVector Extract(Stream source, string filePath, FileContentClassification classification,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(classification);
        cancellationToken.ThrowIfCancellationRequested();
        var vector = new UltronFeatureVector { TargetPath = filePath, Coverage = classification.Coverage,
            CoverageLimitations = classification.CoverageLimitations.ToList() };
        if (!source.CanRead || !source.CanSeek)
        { vector.Coverage = ContentClassificationCoverage.Unknown; vector.CoverageLimitations.Add("SeekableSourceRequired"); return vector; }
        long position = source.Position;
        try
        {
            vector.FileSizeBytes = source.Length;
            source.Position = 0;
            if (!classification.ValidatedFormats.Contains(FileContentFormat.PortableExecutable))
            {
                if (classification.Formats.Contains(FileContentFormat.PortableExecutable))
                { vector.Coverage = ContentClassificationCoverage.Partial; vector.CoverageLimitations.Add("MalformedPeStructure"); }
                return vector;
            }
            int size = (int)Math.Min(source.Length, MaximumPeBytes);
            var data = new byte[size];
            for (int offset = 0; offset < size;)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int read = source.Read(data, offset, Math.Min(64 * 1024, size - offset));
                if (read == 0) throw new EndOfStreamException();
                offset += read;
            }
            vector.EntropyOverall = ComputeShannonEntropy(data, Math.Min(size, EntropySampleBytes));
            if (source.Length > MaximumPeBytes)
            {
                vector.Coverage = ContentClassificationCoverage.Partial;
                vector.CoverageLimitations.Add("PeFeatureByteBudgetExceeded");
                return vector;
            }
            vector.SHA256 = Convert.ToHexString(SHA256.HashData(data));
            ExtractPe(data, vector, cancellationToken);
            return vector;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is IOException or ArgumentException or IndexOutOfRangeException or InvalidOperationException or OverflowException)
        { vector.Coverage = ContentClassificationCoverage.Partial; vector.CoverageLimitations.Add("StaticFeatureReadFailed"); return vector; }
        finally { source.Position = position; }
    }

    private static void ExtractPe(byte[] data, UltronFeatureVector vector, CancellationToken cancellationToken)
    {
        var pe = new PeFile(data);
        var sections = pe.ImageSectionHeaders;
        if (sections == null || sections.Length == 0) throw new InvalidOperationException("PE section metadata is unavailable.");
        vector.SectionCount = sections.Length;
        vector.Subsystem = (int)(pe.ImageNtHeaders?.OptionalHeader.Subsystem ?? 0);
        foreach (var section in sections)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = section.Name?.Trim('\0', ' ') ?? string.Empty;
            if (Packers.Contains(name)) { vector.HasSuspiciousSectionName = true; vector.PrimaryPackerName = name; }
            uint characteristics = (uint)section.Characteristics;
            bool executable = (characteristics & 0x20000000) != 0;
            if (executable && (characteristics & 0x80000000) != 0) vector.HasWritableExecutableSection = true;
            if (section.SizeOfRawData > 0)
                vector.SizeRawVsVirtualRatio = Math.Max(vector.SizeRawVsVirtualRatio, (float)section.VirtualSize / section.SizeOfRawData);
            long offset = section.PointerToRawData, count = Math.Min(section.SizeOfRawData, 256 * 1024);
            if (offset + count > data.Length) throw new InvalidOperationException("PE section exceeds locked content.");
            var sample = data.AsSpan((int)offset, (int)count);
            float entropy = Entropy(sample);
            vector.EntropyMaxSection = Math.Max(vector.EntropyMaxSection, entropy);
            if (executable) vector.EntropyCodeSection = Math.Max(vector.EntropyCodeSection, entropy);
        }
        vector.HasTlsCallbacks = pe.ImageTlsDirectory != null; // Presence only; callback execution is unknown.
        var imports = pe.ImportedFunctions;
        vector.TotalImportsCount = imports?.Length ?? 0;
        if (imports != null) foreach (var import in imports)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string name = import.Name ?? string.Empty;
            bool memory = MemoryApis.Contains(name), injection = InjectionApis.Contains(name), debug = DebugApis.Contains(name);
            vector.HasMemoryAllocationApis |= memory;
            vector.HasProcessInjectionApis |= injection;
            vector.HasAntiDebuggingApis |= debug;
            if (memory || injection || debug) vector.SuspiciousApiCount++; // One import, one contribution.
        }
        vector.DangerousApiRatio = vector.TotalImportsCount == 0 ? 0 : (float)vector.SuspiciousApiCount / vector.TotalImportsCount;
    }

    /// <summary>Returns bounded entropy for a readable source; failures are not silently represented as zero entropy.</summary>
    public static float CalculateFileEntropy(string filePath)
    {
        using var source = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var data = new byte[(int)Math.Min(source.Length, EntropySampleBytes)];
        source.ReadExactly(data);
        return ComputeShannonEntropy(data, data.Length);
    }

    /// <summary>Computes finite Shannon entropy for an explicitly supplied sample.</summary>
    public static float ComputeShannonEntropy(byte[] data, int length)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (length < 0 || length > data.Length) throw new ArgumentOutOfRangeException(nameof(length));
        return Entropy(data.AsSpan(0, length));
    }

    private static float Entropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0;
        Span<int> counts = stackalloc int[256];
        counts.Clear();
        foreach (byte value in data) counts[value]++;
        double entropy = 0;
        foreach (int count in counts)
        {
            if (count == 0) continue;
            double p = (double)count / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return (float)entropy;
    }
}
