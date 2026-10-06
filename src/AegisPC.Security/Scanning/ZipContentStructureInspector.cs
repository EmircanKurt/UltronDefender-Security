using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>Checks bounded ZIP directory/local-header relationships without decompressing untrusted members.</summary>
internal static class ZipContentStructureInspector
{
    private const int MaxEntries = 4096;
    private const int MetadataBudget = 1024 * 1024;
    private const int DisplayMemberLimit = 128;

    internal static async Task InspectAsync(Stream source, byte[] prefix, byte[] tail, long tailOffset,
        FileContentClassification result, CancellationToken ct)
    {
        int end = FindEndRecord(tail);
        bool prefixHint = prefix.AsSpan().StartsWith("PK"u8);
        if (end < 0)
        {
            if (prefixHint)
            {
                result.Formats.Add(FileContentFormat.Zip);
                FileContentClassifier.Limit(result, "ZIP candidate has no supported end record within the bounded tail.");
            }
            return;
        }
        result.Formats.Add(FileContentFormat.Zip);
        ushort entries = BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(end + 10));
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan(end + 12));
        uint offset = BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan(end + 16));
        result.DeclaredArchiveEntryCount = entries;
        if (entries == ushort.MaxValue || size == uint.MaxValue || offset == uint.MaxValue)
        {
            FileContentClassifier.Limit(result, "ZIP64 structural identification is unsupported by this bounded classifier.");
            return;
        }
        if (BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(end + 4)) != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(end + 6)) != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(end + 8)) != entries)
        {
            FileContentClassifier.Limit(result, "Multi-volume or inconsistent ZIP directory is unsupported.");
            return;
        }
        long endOffset = tailOffset + end;
        // EOCD/CD offsets are relative to the archive. This accommodates appended/self-extracting ZIP payloads.
        long archiveBase = endOffset - size - offset;
        long directory = archiveBase + offset;
        if (archiveBase < 0 || directory < 0 || directory > endOffset || size > endOffset - directory)
        {
            FileContentClassifier.Limit(result, "ZIP directory points outside the source boundaries.");
            return;
        }
        if (entries > MaxEntries || size > MetadataBudget)
        {
            FileContentClassifier.Limit(result, "ZIP directory exceeds the 4096-entry or 1 MiB metadata classification budget.");
            return;
        }
        try
        {
            await InspectDirectoryAsync(source, directory, endOffset, archiveBase, entries, result, ct);
        }
        catch (InvalidDataException ex)
        {
            FileContentClassifier.Limit(result, "ZIP structural validation failed: " + ex.Message);
        }
    }

    private static int FindEndRecord(byte[] tail)
    {
        for (int i = tail.Length - 22; i >= 0; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan(i)) != 0x06054b50) continue;
            int comment = BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(i + 20));
            if (i + 22 + comment == tail.Length) return i;
        }
        return -1;
    }

    private static async Task InspectDirectoryAsync(Stream source, long position, long end, long archiveBase,
        int entries, FileContentClassification result, CancellationToken ct)
    {
        long dataEnd = position;
        bool manifest = false, javaClass = false, contentTypes = false, relationship = false, officePart = false;
        for (int i = 0; i < entries; i++)
        {
            ct.ThrowIfCancellationRequested();
            var header = await FileContentClassifier.ReadAtAsync(source, position, 46, ct);
            if (BinaryPrimitives.ReadUInt32LittleEndian(header) != 0x02014b50) throw new InvalidDataException("Central directory signature is invalid.");
            ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(8));
            ushort method = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(10));
            uint compressed = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(20));
            uint expanded = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(24));
            ushort nameLength = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(28));
            ushort extraLength = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(30));
            ushort commentLength = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(32));
            uint localOffset = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(42));
            long next = position + 46L + nameLength + extraLength + commentLength;
            if (nameLength == 0 || nameLength > 4096 || next > end) throw new InvalidDataException("Member metadata exceeds directory boundaries.");
            if (compressed == uint.MaxValue || expanded == uint.MaxValue || localOffset == uint.MaxValue)
                throw new InvalidDataException("ZIP64 member metadata is unsupported.");
            var nameBytes = await FileContentClassifier.ReadAtAsync(source, position + 46, nameLength, ct);
            string name = Encoding.UTF8.GetString(nameBytes);
            long local = archiveBase + localOffset;
            if (local < archiveBase || local > dataEnd - 30) throw new InvalidDataException("Member local header is outside the data region.");
            var localHeader = await FileContentClassifier.ReadAtAsync(source, local, 30, ct);
            if (BinaryPrimitives.ReadUInt32LittleEndian(localHeader) != 0x04034b50) throw new InvalidDataException("Member local header signature is invalid.");
            if (BinaryPrimitives.ReadUInt16LittleEndian(localHeader.AsSpan(6)) != flags ||
                BinaryPrimitives.ReadUInt16LittleEndian(localHeader.AsSpan(8)) != method ||
                BinaryPrimitives.ReadUInt16LittleEndian(localHeader.AsSpan(26)) != nameLength)
                throw new InvalidDataException("Member local and central format metadata disagree.");
            long data = local + 30L + BinaryPrimitives.ReadUInt16LittleEndian(localHeader.AsSpan(26)) + BinaryPrimitives.ReadUInt16LittleEndian(localHeader.AsSpan(28));
            if (data > dataEnd || compressed > dataEnd - data) throw new InvalidDataException("Member content exceeds the data region.");
            bool encrypted = (flags & 1) != 0;
            if (encrypted) FileContentClassifier.Limit(result, "Encrypted ZIP member content cannot be inspected by the configured decoder.");
            if (method is not 0 and not 8) FileContentClassifier.Limit(result, "ZIP member uses an unsupported compression method.");
            if (result.ArchiveMembers.Count < DisplayMemberLimit)
                result.ArchiveMembers.Add(new ArchiveMemberStructure { Name = name, CompressedBytes = compressed, ExpandedBytes = expanded, IsEncrypted = encrypted });
            manifest |= name.Equals("META-INF/MANIFEST.MF", StringComparison.OrdinalIgnoreCase);
            javaClass |= name.EndsWith(".class", StringComparison.OrdinalIgnoreCase);
            contentTypes |= name.Equals("[Content_Types].xml", StringComparison.Ordinal);
            relationship |= name.Equals("_rels/.rels", StringComparison.Ordinal);
            officePart |= name.StartsWith("word/", StringComparison.Ordinal) || name.StartsWith("xl/", StringComparison.Ordinal) || name.StartsWith("ppt/", StringComparison.Ordinal);
            position = next;
        }
        if (position != end) throw new InvalidDataException("Directory length does not match its declared entries.");
        result.ValidatedFormats.Add(FileContentFormat.Zip);
        if (manifest || javaClass) result.Formats.Add(FileContentFormat.JavaArchive);
        if (contentTypes && relationship && officePart) result.Formats.Add(FileContentFormat.OfficeOpenXml);
        result.Observations.Add("ZIP directory and local-header/data boundaries validated; subtype names are candidates, not member safety evidence.");
        if (entries > DisplayMemberLimit) result.Observations.Add("Archive report stores only the first 128 member names; member detection has its separate explicit budget.");
    }
}
