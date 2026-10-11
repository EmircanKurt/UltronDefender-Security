namespace AegisPC.Security.Scanning;

// The shared classifier needs only this routing predicate from the Windows archive inspector.
// This adapter does not copy its detection/decompression logic or establish a trust decision.
internal static class ArchiveEntryInspector
{
    internal static bool HasContainerHeader(ReadOnlySpan<byte> header) =>
        header.StartsWith("PK"u8) || header.StartsWith(new byte[] { 0x1f, 0x8b }) ||
        header.StartsWith("Rar!"u8) || header.StartsWith("BZh"u8) || header.StartsWith("MSCF"u8) ||
        header.StartsWith(new byte[] { 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c }) ||
        header.StartsWith(new byte[] { 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00 });
}
