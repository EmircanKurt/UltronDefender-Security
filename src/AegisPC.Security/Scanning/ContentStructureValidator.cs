using System;
using System.Buffers.Binary;
using System.Linq;
using System.Text;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>Checks bounded structural boundaries without instantiating parsers that execute or decode payloads.</summary>
internal static class ContentStructureValidator
{
    internal static void InspectPrefix(byte[] prefix, byte[] tail, long length, FileContentClassification result)
    {
        ReadOnlySpan<byte> bytes = prefix;
        if (bytes.StartsWith("MZ"u8)) InspectPe(bytes, length, result);
        if (bytes.StartsWith("%PDF-"u8)) InspectPdf(bytes, tail, result);
        if (bytes.StartsWith(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 })) InspectPng(bytes, length, result);
        if (bytes.StartsWith(new byte[] { 0xff, 0xd8, 0xff })) InspectJpeg(bytes, tail, length, result);
        if (bytes.Length >= 20 && BinaryPrimitives.ReadUInt32LittleEndian(bytes) == 0x4c &&
            bytes.Slice(4, 16).SequenceEqual(new byte[] { 1, 20, 2, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46 }))
        {
            result.Formats.Add(FileContentFormat.WindowsShortcut);
            if (length >= 76) result.ValidatedFormats.Add(FileContentFormat.WindowsShortcut);
            FileContentClassifier.Limit(result, "Shell Link header identified; target and additional link structures were not resolved or executed.");
        }
        if (!bytes.StartsWith("PK"u8) && ArchiveEntryInspector.HasContainerHeader(bytes[..Math.Min(6, bytes.Length)]))
        {
            result.Formats.Add(FileContentFormat.UnsupportedContainer);
            FileContentClassifier.Limit(result, "Observed container is unsupported by the configured member decoder.", ContentClassificationCoverage.Unsupported);
        }
    }

    private static void InspectPe(ReadOnlySpan<byte> bytes, long length, FileContentClassification result)
    {
        result.Formats.Add(FileContentFormat.PortableExecutable);
        bool valid = false;
        if (bytes.Length >= 64)
        {
            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(bytes[60..]);
            if (offset >= 64 && offset <= bytes.Length - 24)
            {
                int start = (int)offset;
                if (bytes.Slice(start, 4).SequenceEqual(new byte[] { 0x50, 0x45, 0, 0 }))
                {
                    ushort sections = BinaryPrimitives.ReadUInt16LittleEndian(bytes[(start + 6)..]);
                    ushort optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(bytes[(start + 20)..]);
                    ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(bytes[(start + 22)..]);
                    int optional = start + 24;
                    int table = optional + optionalSize;
                    if (sections is > 0 and <= 96 && optionalSize >= 96 && table <= bytes.Length - sections * 40 && (characteristics & 2) != 0)
                    {
                        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(bytes[optional..]);
                        valid = magic == 0x10b || magic == 0x20b && optionalSize >= 112;
                        uint headerSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(optional + 60)..]);
                        valid &= headerSize >= table + sections * 40 && headerSize <= length;
                        for (int i = 0; valid && i < sections; i++)
                        {
                            int section = table + i * 40;
                            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(section + 16)..]);
                            uint rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(section + 20)..]);
                            if (rawSize > 0 && (rawOffset < headerSize || rawOffset > length || rawSize > length - rawOffset)) valid = false;
                        }
                    }
                }
            }
        }
        if (valid)
        {
            result.ValidatedFormats.Add(FileContentFormat.PortableExecutable);
            result.Observations.Add("PE signature, COFF/optional header and section file boundaries validated; imports and payload require detector inspection.");
        }
        else FileContentClassifier.Limit(result, "MZ candidate did not pass bounded PE header and section boundary validation.");
    }

    private static void InspectPdf(ReadOnlySpan<byte> prefix, byte[] tail, FileContentClassification result)
    {
        result.Formats.Add(FileContentFormat.Pdf);
        bool version = prefix.Length >= 8 && prefix[5] is >= (byte)'1' and <= (byte)'2' && prefix[6] == '.' && prefix[7] is >= (byte)'0' and <= (byte)'9';
        if (version && tail.AsSpan().LastIndexOf("%%EOF"u8) >= 0 && tail.AsSpan().LastIndexOf("startxref"u8) >= 0)
            result.ValidatedFormats.Add(FileContentFormat.Pdf);
        FileContentClassifier.Limit(result, "PDF candidate identified; embedded objects and cross-reference graph require a decoder not configured here.");
    }

    private static void InspectPng(ReadOnlySpan<byte> bytes, long length, FileContentClassification result)
    {
        result.Formats.Add(FileContentFormat.Png);
        int position = 8;
        bool ihdr = false, idat = false, ended = false;
        for (int count = 0; count < 4096 && position <= bytes.Length - 12; count++)
        {
            uint size = BinaryPrimitives.ReadUInt32BigEndian(bytes[position..]);
            long end = position + 12L + size;
            if (end > bytes.Length) break;
            var type = bytes.Slice(position + 4, 4);
            if (count == 0)
            {
                ihdr = type.SequenceEqual("IHDR"u8) && size == 13 &&
                    BinaryPrimitives.ReadUInt32BigEndian(bytes[(position + 8)..]) > 0 &&
                    BinaryPrimitives.ReadUInt32BigEndian(bytes[(position + 12)..]) > 0;
                if (!ihdr) break;
            }
            if (type.SequenceEqual("IDAT"u8)) idat = true;
            if (type.SequenceEqual("IEND"u8)) { ended = size == 0 && end == length; break; }
            position = (int)end;
        }
        if (ihdr && idat && ended)
        {
            result.ValidatedFormats.Add(FileContentFormat.Png);
            result.Observations.Add("PNG IHDR/IDAT/IEND chunk boundaries validated; pixel content is not executed or decoded.");
        }
        else FileContentClassifier.Limit(result, "PNG chunk validation was malformed, truncated or exceeded the bounded prefix.");
    }

    private static void InspectJpeg(ReadOnlySpan<byte> bytes, byte[] tail, long length, FileContentClassification result)
    {
        result.Formats.Add(FileContentFormat.Jpeg);
        int offset = 2;
        bool frame = false, scan = false;
        while (offset <= bytes.Length - 4)
        {
            if (bytes[offset++] != 0xff) break;
            while (offset < bytes.Length && bytes[offset] == 0xff) offset++;
            if (offset >= bytes.Length) break;
            byte marker = bytes[offset++];
            if (marker is 0xd8 or 0x01 || marker is >= 0xd0 and <= 0xd7) continue;
            if (marker == 0xd9) break;
            ushort segmentLength = BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]);
            if (segmentLength < 2 || offset + segmentLength > bytes.Length) break;
            if (marker is >= 0xc0 and <= 0xcf && marker is not 0xc4 and not 0xc8 and not 0xcc)
                frame = segmentLength >= 8 && BinaryPrimitives.ReadUInt16BigEndian(bytes[(offset + 3)..]) > 0 && BinaryPrimitives.ReadUInt16BigEndian(bytes[(offset + 5)..]) > 0;
            if (marker == 0xda) { scan = segmentLength >= 6; break; }
            offset += segmentLength;
        }
        bool ended = tail.Length >= 2 && tail[^2] == 0xff && tail[^1] == 0xd9;
        if (frame && scan && ended)
        {
            result.ValidatedFormats.Add(FileContentFormat.Jpeg);
            result.Observations.Add("JPEG frame/scan marker boundaries and end marker validated; image decoding remains outside this classifier.");
        }
        else FileContentClassifier.Limit(result, "JPEG marker validation was malformed, truncated or exceeded the bounded prefix.");
    }
}
