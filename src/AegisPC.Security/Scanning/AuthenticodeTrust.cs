using System;
using System.IO;
using System.Runtime.InteropServices;

namespace AegisPC.Security.Scanning;

/// <summary>Windows file and catalog trust verification against an already locked file.</summary>
internal static class AuthenticodeTrust
{
    internal const int NoSignature = unchecked((int)0x800B0100);
    private static readonly Guid Action = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FileInfoNative
    {
        public uint Size;
        [MarshalAs(UnmanagedType.LPWStr)] public string Path;
        public IntPtr Handle, Subject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint Size;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Path;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogTrust
    {
        public uint Size, Version;
        [MarshalAs(UnmanagedType.LPWStr)] public string CatalogPath;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberPath;
        public IntPtr MemberFile, Hash;
        public uint HashSize;
        public IntPtr CatalogContext, Admin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        public uint Size;
        public IntPtr Policy, Sip;
        public uint UiChoice, Revocation, UnionChoice;
        public IntPtr Subject;
        public uint StateAction;
        public IntPtr State, Url;
        public uint Flags, UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr window, in Guid action, ref TrustData data);
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string algorithm, IntPtr policy, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, IntPtr file, ref uint size, byte[]? hash, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint size, uint flags, IntPtr previous);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogInfo info, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);

    internal static int Verify(FileStream file, out string certificatePath)
    {
        certificatePath = file.Name;
        var info = new FileInfoNative { Size = (uint)Marshal.SizeOf<FileInfoNative>(),
            Path = file.Name, Handle = file.SafeFileHandle.DangerousGetHandle() };
        int status = VerifySubject(info, 1);
        if (status != NoSignature) return status;
        // A matching catalog alone is NOT proof of trust. Verify the member and catalog together.
        foreach (var algorithm in new[] { "SHA256", "SHA1" })
        {
            int catalogStatus = VerifyCatalog(file, algorithm, out var catalogPath);
            if (catalogStatus != NoSignature)
            {
                certificatePath = catalogPath;
                return catalogStatus;
            }
        }
        return status;
    }

    private static int VerifyCatalog(FileStream file, string algorithm, out string catalogPath)
    {
        catalogPath = file.Name;
        if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
            return NoSignature;
        try
        {
            var handle = file.SafeFileHandle.DangerousGetHandle();
            uint size = 0;
            file.Position = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, null, 0) || size == 0)
                return NoSignature;
            var hash = new byte[size];
            file.Position = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, hash, 0)) return NoSignature;
            var catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
            if (catalog == IntPtr.Zero) return NoSignature;
            try
            {
                var info = new CatalogInfo { Size = (uint)Marshal.SizeOf<CatalogInfo>(), Path = string.Empty };
                if (!CryptCATCatalogInfoFromContext(catalog, ref info, 0)) return NoSignature;
                catalogPath = info.Path;
                using var catalogLock = new FileStream(info.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                var pinnedHash = GCHandle.Alloc(hash, GCHandleType.Pinned);
                try
                {
                    return VerifySubject(new CatalogTrust
                    {
                        Size = (uint)Marshal.SizeOf<CatalogTrust>(), CatalogPath = info.Path,
                        MemberTag = Convert.ToHexString(hash), MemberPath = file.Name,
                        MemberFile = handle, Hash = pinnedHash.AddrOfPinnedObject(), HashSize = size, Admin = admin
                    }, 2);
                }
                finally { pinnedHash.Free(); }
            }
            finally { CryptCATAdminReleaseCatalogContext(admin, catalog, 0); }
        }
        finally { CryptCATAdminReleaseContext(admin, 0); }
    }

    private static int VerifySubject<T>(T subject, uint choice) where T : struct
    {
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        bool marshalled = false;
        try
        {
            Marshal.StructureToPtr(subject, pointer, false);
            marshalled = true;
            var data = new TrustData { Size = (uint)Marshal.SizeOf<TrustData>(), UiChoice = 2,
                UnionChoice = choice, Subject = pointer, StateAction = 1,
                // Cache-only retrieval + revocation checking excluding the root. Unknown is not valid.
                Flags = 0x1000 | 0x80 };
            try { return WinVerifyTrust(new IntPtr(-1), in Action, ref data); }
            finally
            {
                data.StateAction = 2;
                WinVerifyTrust(new IntPtr(-1), in Action, ref data);
            }
        }
        finally
        {
            if (marshalled) Marshal.DestroyStructure<T>(pointer);
            Marshal.FreeHGlobal(pointer);
        }
    }
}
