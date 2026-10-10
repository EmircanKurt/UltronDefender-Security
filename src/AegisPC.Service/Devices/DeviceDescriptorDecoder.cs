using System.Buffers.Binary;
using AegisPC.Core.Models.Devices;

namespace AegisPC.Service.Devices;

/// <summary>Pure, bounded descriptor decoding; suitable for inert fixtures without opening a device.</summary>
public static class DeviceDescriptorDecoder
{
    /// <summary>Reads STORAGE_DEVICE_DESCRIPTOR.BusType only when the returned and advertised sizes cover it.</summary>
    public static uint? ReadStorageBusType(ReadOnlySpan<byte> descriptor, int returnedBytes)
    {
        if (returnedBytes < 36 || returnedBytes > descriptor.Length) return null;
        uint advertised = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.Slice(4, 4));
        if (advertised < 36 || advertised > returnedBytes || advertised > WindowsDeviceNative.MaximumBufferBytes) return null;
        return BinaryPrimitives.ReadUInt32LittleEndian(descriptor.Slice(28, 4));
    }

    /// <summary>Queries report transport only. A USB descriptor or parent enumerator never establishes authenticity.</summary>
    public static UsbAssociation ClassifyUsb(uint? busType, bool observedUsbAncestor, bool completeAncestry)
    {
        if (busType == 7 || observedUsbAncestor) return UsbAssociation.Usb; // STORAGE_BUS_TYPE.BusTypeUsb.
        return completeAncestry && busType.HasValue && busType.Value != 0
            ? UsbAssociation.NotUsb : UsbAssociation.Unknown;
    }

    /// <summary>Decodes physical disk numbers with the SDK's eight-byte extent alignment and a 128-extent cap.</summary>
    public static IReadOnlyList<uint>? ReadVolumeDiskNumbers(ReadOnlySpan<byte> buffer, int returnedBytes)
    {
        if (returnedBytes < 8 || returnedBytes > buffer.Length) return null;
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(buffer[..4]);
        if (count == 0 || count > 128 || 8L + count * 24L > returnedBytes) return null;
        var result = new HashSet<uint>();
        for (int i = 0; i < count; i++)
            result.Add(BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(8 + i * 24, 4)));
        return Array.AsReadOnly(result.Order().ToArray());
    }
}
