using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Security.Safety;

/// <summary>Holds the source identity and denies writers until handle-specific deletion.</summary>
internal sealed class QuarantineSourceHandle : IDisposable
{
    public FileStream Stream { get; }
    public string FinalPath { get; }

    public QuarantineSourceHandle(string path)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Handle-bound quarantine requires Windows.");
        // GENERIC_READ | DELETE; share only reads. No writer or path replacement can
        // slip between the vault snapshot and removal of this exact file object.
        if (path.Length >= 260 && !path.StartsWith(@"\\?\", StringComparison.Ordinal))
            path = path.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + path[2..] : @"\\?\" + path;
        var handle = CreateFileW(path, 0x80010000, 1, IntPtr.Zero, 3, 0x48200000, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("Özgün dosya güvenle açılamadığı için kaldırılamadı.", new Win32Exception(error));
        }
        try
        {
            if (!GetFileInformationByHandleEx(handle, 9, out var attributes, 8))
                throw new IOException("Kaynak dosya özellikleri güvenle doğrulanamadı.", new Win32Exception(Marshal.GetLastWin32Error()));
            if ((attributes.Attributes & (uint)FileAttributes.ReparsePoint) != 0)
                throw new IOException("Kaynak dosya bir reparse point; hedefe dokunulmadı.");
            var name = new StringBuilder(1024);
            uint length = GetFinalPathNameByHandleW(handle, name, (uint)name.Capacity, 0);
            if (length >= name.Capacity)
            {
                name = new StringBuilder(checked((int)length + 1));
                length = GetFinalPathNameByHandleW(handle, name, (uint)name.Capacity, 0);
            }
            if (length == 0 || length >= name.Capacity)
                throw new IOException("Kaynak dosyanın gerçek yolu doğrulanamadı.");
            string final = name.ToString();
            FinalPath = final.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ? @"\\" + final[8..] :
                final.StartsWith(@"\\?\", StringComparison.Ordinal) ? final[4..] : final;
            Stream = new FileStream(handle, FileAccess.Read, 81920, isAsync: true);
        }
        catch { handle.Dispose(); throw; }
    }

    public void MarkForDeletion()
    {
        // Windows 10 1809+: ignore READONLY without changing source attributes by path.
        uint flags = 0x11; // FILE_DISPOSITION_FLAG_DELETE | IGNORE_READONLY_ATTRIBUTE
        if (SetFileInformationByHandleEx(Stream.SafeFileHandle, 21, ref flags, sizeof(uint))) return;
        int error = Marshal.GetLastWin32Error();
        if (error is not (1 or 50 or 87))
            throw new IOException("Özgün dosya güvenle kaldırılamadı.", new Win32Exception(error));
        var disposition = new FileDispositionInfo { DeleteFile = true };
        if (!SetFileInformationByHandle(Stream.SafeFileHandle, 4, ref disposition, (uint)Marshal.SizeOf<FileDispositionInfo>()))
            throw new IOException("Özgün dosya kullanımda veya erişim engelli olduğu için kaldırılamadı.", new Win32Exception(Marshal.GetLastWin32Error()));
    }

    public void Dispose() => Stream.Dispose();

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInfo { [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo { public uint Attributes; public uint Tag; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, ref FileDispositionInfo info, uint size);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, ref uint flags, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, out FileAttributeTagInfo info, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
}
