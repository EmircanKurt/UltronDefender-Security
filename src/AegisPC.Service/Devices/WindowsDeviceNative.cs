using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Service.Devices;

/// <summary>Read-only PnP/HID interop. Constants and layouts follow the Microsoft Windows SDK.</summary>
internal static class WindowsDeviceNative
{
    internal static readonly Guid DiskInterface = new("53f56307-b6bf-11d0-94f2-00a0c91efb8b");
    internal static readonly Guid HidInterface = new("4d1e55b2-f16f-11cf-88cb-001111000030");
    internal const int MaximumBufferBytes = 65536;
    internal const uint NoMoreItems = 259;

    [StructLayout(LayoutKind.Sequential)]
    internal struct InterfaceData
    {
        internal uint Size;
        internal Guid ClassGuid;
        internal uint Flags;
        internal UIntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DeviceInfoData
    {
        internal uint Size;
        internal Guid ClassGuid;
        internal uint DevInst;
        internal UIntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PropertyKey
    {
        internal Guid FormatId;
        internal uint PropertyId;
        internal PropertyKey(Guid format, uint property) { FormatId = format; PropertyId = property; }
    }

    // CM_NOTIFY_FILTER's largest union member is WCHAR InstanceId[MAX_DEVICE_ID_LEN=200].
    [StructLayout(LayoutKind.Explicit, Size = 416)]
    internal struct NotificationFilter
    {
        [FieldOffset(0)] internal uint Size;
        [FieldOffset(4)] internal uint Flags;
        [FieldOffset(8)] internal uint FilterType;
        [FieldOffset(12)] internal uint Reserved;
        [FieldOffset(16)] internal Guid ClassGuid;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate uint NotificationCallback(IntPtr registration, IntPtr context, uint action,
        IntPtr eventData, uint eventDataSize);

    [DllImport("cfgmgr32.dll", ExactSpelling = true)]
    internal static extern uint CM_Register_Notification(ref NotificationFilter filter, IntPtr context,
        NotificationCallback callback, out IntPtr registration);
    [DllImport("cfgmgr32.dll", ExactSpelling = true)]
    internal static extern uint CM_Unregister_Notification(IntPtr registration);
    [DllImport("cfgmgr32.dll", ExactSpelling = true)]
    internal static extern uint CM_Get_Parent(out uint parent, uint devInst, uint flags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    internal static extern uint CM_Get_Device_IDW(uint devInst, StringBuilder buffer, uint bufferLength, uint flags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    internal static extern uint CM_Get_DevNode_PropertyW(uint devInst, ref PropertyKey property,
        out uint propertyType, byte[]? buffer, ref uint bufferSize, uint flags);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr SetupDiGetClassDevsW(ref Guid classGuid, string? enumerator, IntPtr parent, uint flags);
    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetupDiEnumDeviceInterfaces(IntPtr set, IntPtr device, ref Guid classGuid,
        uint memberIndex, ref InterfaceData data);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetupDiGetDeviceInterfaceDetailW(IntPtr set, ref InterfaceData data,
        IntPtr detail, uint size, out uint requiredSize, ref DeviceInfoData deviceInfo);
    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);

    [DllImport("hid.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static extern bool HidD_GetPreparsedData(SafeFileHandle handle, out IntPtr preparsedData);
    [DllImport("hid.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static extern bool HidD_FreePreparsedData(IntPtr preparsedData);
    [DllImport("hid.dll", ExactSpelling = true)]
    internal static extern int HidP_GetCaps(IntPtr preparsedData, IntPtr capabilities);
}
