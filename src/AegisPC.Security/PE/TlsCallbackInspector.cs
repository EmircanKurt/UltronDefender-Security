using System.Buffers.Binary;

namespace AegisPC.Security.PE;

/// <summary>Validates on-disk PE TLS callback structures without executing callbacks or mistaking TLS data for attack evidence.</summary>
internal static class TlsCallbackInspector
{
    internal static (bool HasDirectory, int CallbackCount, bool Complete) Inspect(ReadOnlySpan<byte> data)
    {
        if (data.Length < 64 || data[0] != 'M' || data[1] != 'Z') return (false, 0, false);
        uint peOffset = U32(data, 60);
        if (peOffset > data.Length - 24) return (false, 0, false);
        int pe = (int)peOffset;
        if (U32(data, pe) != 0x4550) return (false, 0, false);
        int optional = pe + 24, optionalSize = U16(data, pe + 20);
        if (optionalSize < 2 || optionalSize > data.Length - optional) return (false, 0, false);
        ushort magic = U16(data, optional);
        if (magic is not (0x10b or 0x20b)) return (false, 0, false);
        bool wide = magic == 0x20b;
        int directoryBase = wide ? 112 : 96;
        if (optionalSize < directoryBase) return (false, 0, false);
        if (U32(data, optional + directoryBase - 4) <= 9) return (false, 0, true);
        if (optionalSize < directoryBase + 80) return (false, 0, false);
        uint rva = U32(data, optional + directoryBase + 72);
        uint size = U32(data, optional + directoryBase + 76);
        if (rva == 0 && size == 0) return (false, 0, true);
        int table = optional + optionalSize, sections = U16(data, pe + 6);
        uint headers = U32(data, optional + 60);
        int tlsSize = wide ? 40 : 24;
        int tls = Map(data, rva, tlsSize, table, sections, headers);
        if (size < tlsSize || tls < 0) return (true, 0, false);
        ulong imageBase = wide ? U64(data, optional + 24) : U32(data, optional + 28);
        ulong callbacks = wide ? U64(data, tls + 24) : U32(data, tls + 12);
        if (callbacks == 0) return (true, 0, true);
        if (callbacks < imageBase || callbacks - imageBase > uint.MaxValue) return (true, 0, false);
        uint callbackRva = (uint)(callbacks - imageBase);
        int width = wide ? 8 : 4;
        for (int count = 0; count <= 256; count++)
        {
            ulong entryRva = (ulong)callbackRva + (uint)(count * width);
            if (entryRva > uint.MaxValue) return (true, 0, false);
            int entry = Map(data, (uint)entryRva, width, table, sections, headers);
            if (entry < 0) return (true, 0, false);
            ulong address = wide ? U64(data, entry) : U32(data, entry);
            if (address == 0) return (true, count, true);
            if (count == 256 || address < imageBase || address - imageBase > uint.MaxValue ||
                Map(data, (uint)(address - imageBase), 1, table, sections, headers) < 0)
                return (true, 0, false);
        }
        return (true, 0, false);
    }

    private static int Map(ReadOnlySpan<byte> data, uint rva, int width, int table, int sections, uint headers)
    {
        ulong end = (ulong)rva + (uint)width;
        if (end <= headers && end <= (ulong)data.Length) return (int)rva;
        if (sections > 4096 || table > data.Length || sections * 40 > data.Length - table) return -1;
        for (int i = 0; i < sections; i++)
        {
            int section = table + i * 40;
            uint va = U32(data, section + 12), rawSize = U32(data, section + 16), raw = U32(data, section + 20);
            if (rva < va || end > (ulong)va + rawSize) continue;
            ulong offset = (ulong)raw + rva - va;
            if (offset + (uint)width <= (ulong)data.Length) return (int)offset;
        }
        return -1;
    }

    private static ushort U16(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));
    private static uint U32(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
    private static ulong U64(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, 8));
}
