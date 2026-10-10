using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Security.Safety;

/// <summary>Opens a non-reparse, single-link lock and hardens its ACL through the same exclusively held file object.</summary>
internal static class VaultLockFile
{
    private const uint OwnerAndDacl = 0x00000005;
    private const uint ProtectedDacl = 0x80000000;

    internal static FileStream Open(string path, bool customVault)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Vault locking requires Windows.");
        byte[] security = VaultSecurityPolicy.CreateLockAcl(customVault).GetSecurityDescriptorBinaryForm();
        var pinned = GCHandle.Alloc(security, GCHandleType.Pinned);
        SafeFileHandle? handle = null;
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = pinned.AddrOfPinnedObject(), InheritHandle = false
            };
            // GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER.
            // OPEN_REPARSE_POINT prevents SYSTEM from following a legacy redirect even when a path check raced.
            handle = CreateFileW(path, 0xC00E0000, 0, ref attributes, 4, 0x00200080, IntPtr.Zero);
            if (handle.IsInvalid) throw IoError("Vault lock could not be opened exclusively.");
            if (!GetFileInformationByHandle(handle, out var file)) throw IoError("Vault lock identity could not be verified.");
            if ((file.Attributes & (uint)FileAttributes.ReparsePoint) != 0 || file.NumberOfLinks != 1)
                throw new IOException("Vault lock must be a non-reparse, single-link file.");
            ApplyAndVerifyAcl(handle, pinned.AddrOfPinnedObject(), customVault);
            var stream = new FileStream(handle, FileAccess.ReadWrite);
            handle = null; // The returned FileStream now owns this handle.
            return stream;
        }
        finally { handle?.Dispose(); pinned.Free(); }
    }

    private static void ApplyAndVerifyAcl(SafeFileHandle handle, IntPtr security, bool customVault)
    {
        if (!GetSecurityDescriptorOwner(security, out var owner, out _) || owner == IntPtr.Zero ||
            !GetSecurityDescriptorDacl(security, out bool present, out var dacl, out _) || !present || dacl == IntPtr.Zero)
            throw new IOException("The restrictive lock security descriptor could not be constructed.");
        uint error = SetSecurityInfo(handle, 1, OwnerAndDacl | ProtectedDacl, owner, IntPtr.Zero, dacl, IntPtr.Zero);
        if (error != 0) throw new IOException("Vault lock ACL installation failed; operations stopped.", new Win32Exception((int)error));
        error = GetSecurityInfo(handle, 1, OwnerAndDacl, out _, out _, out _, out _, out var descriptor);
        try
        {
            if (error != 0 || descriptor == IntPtr.Zero)
                throw new IOException("Vault lock ACL verification could not be read.", new Win32Exception((int)error));
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length == 0 || length > 4096) throw new IOException("The installed lock ACL has an unexpected descriptor size.");
            byte[] actual = new byte[length];
            Marshal.Copy(descriptor, actual, 0, actual.Length);
            var acl = new FileSecurity();
            acl.SetSecurityDescriptorBinaryForm(actual);
            if (!VaultSecurityPolicy.IsStrictFileAcl(acl, customVault))
                throw new IOException("Vault lock ACL verification failed; operations stopped.");
        }
        finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
    }

    private static IOException IoError(string message)
    {
        int error = Marshal.GetLastWin32Error();
        return new IOException(message, new Win32Exception(error));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr Descriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint SizeHigh;
        public uint SizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        ref SecurityAttributes security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorOwner(IntPtr descriptor, out IntPtr owner, out bool defaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, out bool present, out IntPtr dacl, out bool defaulted);

    [DllImport("advapi32.dll")]
    private static extern uint SetSecurityInfo(SafeFileHandle handle, int objectType, uint information,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint information,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
