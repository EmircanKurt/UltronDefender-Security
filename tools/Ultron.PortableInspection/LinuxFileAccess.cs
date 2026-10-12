using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Ultron.PortableInspection;

// Linux UAPI statx layout is fixed at 256 bytes on supported x64/arm64 targets.
// Verified references and the supported glibc/kernel baseline are in LINUX_PREVIEW.md.
internal static class LinuxFileAccess
{
    private const int PathOnlyNoFollow = 0x200000 | 0x80000 | 0x20000; // O_PATH, CLOEXEC, NOFOLLOW
    private const int DirectoryFlag = 0x10000;
    private const uint RequiredMetadata = 0x3c1; // TYPE, INO, SIZE, MTIME, CTIME

    internal static void RequireSupportedPlatform()
    {
        if (!OperatingSystem.IsLinux() || RuntimeInformation.ProcessArchitecture is not Architecture.X64 and not Architecture.Arm64)
            throw new PlatformNotSupportedException("Native scope inspection requires Linux x64/arm64 with glibc statx support.");
    }

    internal static SafeFileHandle OpenSelectedPath(string path)
    {
        RequireSupportedPlatform();
        string absolute = Path.GetFullPath(path);
        string[] parts = absolute.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Length > 128) throw new IOException("Root scope or excessive path depth is unsupported.");
        SafeFileHandle current = OpenAt(-100, "/", true);
        try
        {
            for (int index = 0; index < parts.Length; index++)
            {
                var next = OpenAt(Fd(current), parts[index], index < parts.Length - 1);
                current.Dispose();
                current = next;
            }
            return current;
        }
        catch { current.Dispose(); throw; }
    }

    internal static SafeFileHandle OpenChild(SafeFileHandle parent, string name)
    {
        if (name.Contains('/') || name is "." or "..") throw new IOException("Invalid directory entry name.");
        return OpenAt(Fd(parent), name, false);
    }

    internal static FileMetadata Metadata(SafeFileHandle handle)
    {
        int status = Statx(Fd(handle), "", 0x1000, RequiredMetadata, out var data); // AT_EMPTY_PATH
        if (status != 0) throw NativeError("statx");
        if ((data.Mask & RequiredMetadata) != RequiredMetadata) throw new IOException("Required stable file metadata is unavailable.");
        return new(data.Mode & 0xf000, data.Size, data.Inode, data.DeviceMajor, data.DeviceMinor,
            data.ModifiedSeconds, data.ModifiedNanoseconds, data.ChangedSeconds, data.ChangedNanoseconds);
    }

    internal static string EnumerationPath(SafeFileHandle directory) => $"/proc/self/fd/{Fd(directory)}";

    internal static SafeFileHandle OpenForRead(SafeFileHandle pinnedNode, FileMetadata expected)
    {
        if (!expected.IsRegularFile) throw new IOException("Only a verified regular node can be opened for reading.");
        int descriptor = NativeOpenAt(-100, EnumerationPath(pinnedNode), 0x80000 | 0x800); // CLOEXEC, NONBLOCK
        if (descriptor < 0) throw NativeError("open pinned regular node");
        var reader = new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
        try
        {
            if (Metadata(reader) != expected) throw new IOException("Source changed before the bounded read began.");
            return reader;
        }
        catch { reader.Dispose(); throw; }
    }

    private static SafeFileHandle OpenAt(int parent, string path, bool directory)
    {
        int descriptor = NativeOpenAt(parent, path, PathOnlyNoFollow | (directory ? DirectoryFlag : 0));
        if (descriptor < 0) throw NativeError("openat (links and special nodes are not followed)");
        return new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
    }

    private static int Fd(SafeFileHandle handle) => checked((int)handle.DangerousGetHandle());
    private static IOException NativeError(string operation) => new($"{operation} failed: {new Win32Exception(Marshal.GetLastPInvokeError()).Message}");

    [DllImport("libc", EntryPoint = "openat", SetLastError = true)]
    private static extern int NativeOpenAt(int directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(int directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out NativeStatx data);

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct NativeStatx
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(40)] internal ulong Size;
        [FieldOffset(96)] internal long ChangedSeconds;
        [FieldOffset(104)] internal uint ChangedNanoseconds;
        [FieldOffset(112)] internal long ModifiedSeconds;
        [FieldOffset(120)] internal uint ModifiedNanoseconds;
        [FieldOffset(136)] internal uint DeviceMajor;
        [FieldOffset(140)] internal uint DeviceMinor;
    }
}

internal sealed record FileMetadata(int Kind, ulong Size, ulong Inode, uint DeviceMajor, uint DeviceMinor,
    long ModifiedSeconds, uint ModifiedNanoseconds, long ChangedSeconds, uint ChangedNanoseconds)
{
    internal bool IsDirectory => Kind == 0x4000;
    internal bool IsRegularFile => Kind == 0x8000;
    internal bool SameDevice(FileMetadata other) => DeviceMajor == other.DeviceMajor && DeviceMinor == other.DeviceMinor;
}
