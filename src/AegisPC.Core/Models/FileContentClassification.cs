using System.Collections.Generic;
using System.Linq;

namespace AegisPC.Core.Models;

/// <summary>Identifies observed structures, never whether their contents are safe.</summary>
public enum FileContentFormat
{
    /// <summary>No supported structure was established.</summary>
    Unknown,
    /// <summary>DOS, COFF, optional and section table boundaries were validated.</summary>
    PortableExecutable,
    /// <summary>A bounded ZIP central directory was identified.</summary>
    Zip,
    /// <summary>ZIP metadata includes Java archive structure; member bytecode still requires inspection.</summary>
    JavaArchive,
    /// <summary>ZIP metadata includes an OOXML package structure; document content is not executed.</summary>
    OfficeOpenXml,
    /// <summary>A PDF header and ending were observed; embedded objects are not decoded by classification.</summary>
    Pdf,
    /// <summary>PNG chunk boundaries were observed; pixel decoding is outside classification.</summary>
    Png,
    /// <summary>JPEG frame markers were observed; pixel decoding is outside classification.</summary>
    Jpeg,
    /// <summary>The bounded sample is decodable text, not a safety determination.</summary>
    Text,
    /// <summary>Text has a script grammar hint; this is a routing candidate, not malware evidence.</summary>
    ScriptCandidate,
    /// <summary>A Shell Link header was observed; its target is neither followed nor executed.</summary>
    WindowsShortcut,
    /// <summary>A known container hint is unsupported by the configured member parser.</summary>
    UnsupportedContainer
}

/// <summary>Describes whether the configured structural identification was completed within its budget.</summary>
public enum ContentClassificationCoverage
{
    /// <summary>Configured structure checks completed; this does not mean malware-free.</summary>
    Complete,
    /// <summary>A candidate exists but a structure, parser or budget limit prevented complete identification.</summary>
    Partial,
    /// <summary>No configured decoder supports the observed container.</summary>
    Unsupported,
    /// <summary>The observed bytes could not be assigned a supported structure.</summary>
    Unknown
}

/// <summary>Stores bounded archive metadata for explanatory reports without extracting or executing members.</summary>
public sealed class ArchiveMemberStructure
{
    /// <summary>Returns the member's declared archive-relative name; this is untrusted metadata.</summary>
    public string Name { get; init; } = string.Empty;
    /// <summary>Returns the declared expanded size, not a promise that decompression is safe.</summary>
    public long ExpandedBytes { get; init; }
    /// <summary>Returns the declared compressed size.</summary>
    public long CompressedBytes { get; init; }
    /// <summary>Identifies members whose encrypted content cannot be inspected by the configured parser.</summary>
    public bool IsEncrypted { get; init; }
}

/// <summary>
/// Reports content identity independently of its filename. Complete classification is not a clean-file verdict;
/// callers must still perform hash, rules and appropriate content inspection on the same locked source.
/// </summary>
public sealed class FileContentClassification
{
    /// <summary>Returns format candidates supported by the observed structural bytes.</summary>
    public List<FileContentFormat> Formats { get; } = new();
    /// <summary>Identifies formats whose configured boundary validation completed, distinct from magic-byte candidates.</summary>
    public List<FileContentFormat> ValidatedFormats { get; } = new();
    /// <summary>Returns the lower-cased filename extension as a display hint only.</summary>
    public string DeclaredExtension { get; init; } = string.Empty;
    /// <summary>Reports completion of configured identification, independent of malware findings.</summary>
    public ContentClassificationCoverage Coverage { get; set; } = ContentClassificationCoverage.Complete;
    /// <summary>Explains malformed, unknown, encrypted or unsupported structural coverage.</summary>
    public List<string> CoverageLimitations { get; } = new();
    /// <summary>Explains validated structures and candidates without contributing a malware score.</summary>
    public List<string> Observations { get; } = new();
    /// <summary>Flags contradictory declared and observed known formats; not independently malicious.</summary>
    public bool HasExtensionMismatch { get; set; }
    /// <summary>Flags multiple independently observed top-level structures, excluding ordinary ZIP package subtypes.</summary>
    public bool IsAmbiguous { get; set; }
    /// <summary>Returns bounded member metadata; omitted names are explicitly reported.</summary>
    public List<ArchiveMemberStructure> ArchiveMembers { get; } = new();
    /// <summary>Returns the number of entries declared by the ZIP end record.</summary>
    public int? DeclaredArchiveEntryCount { get; set; }
    /// <summary>Reports that the common ZIP member inspector must run even when the filename is disguised.</summary>
    public bool RequiresZipInspection => Formats.Any(f => f is FileContentFormat.Zip or FileContentFormat.JavaArchive or FileContentFormat.OfficeOpenXml);
    /// <summary>Reports that structural identification has no omissions; never establishes trust.</summary>
    public bool IsComplete => Coverage == ContentClassificationCoverage.Complete && CoverageLimitations.Count == 0;
}
