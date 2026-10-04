using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using AegisPC.Core.Helpers;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Security.RealTime
{
    /// <summary>Manages harmless decoys owned by this observer instance, without adopting user files.</summary>
    public interface ICanaryTrapManager
    {
        /// <summary>Number of owned records; an observed deletion may remain recorded until redeployment or cleanup.</summary>
        int CanaryFileCount { get; }

        /// <summary>Indicates manager cleanup so its own removals can be excluded from observer alerts.</summary>
        bool IsCleaningUpCanaries { get; }

        /// <summary>Snapshot of exact paths created by this instance, including pending deletion observations.</summary>
        IReadOnlyList<string> CanaryFiles { get; }

        /// <summary>Creates new local decoys and retains verified live ownership; existing files are never adopted.</summary>
        void DeployCanaries(IEnumerable<string> protectedDirs);

        /// <summary>Deletes only recorded identities through verified handles; inaccessible owned files may remain.</summary>
        void CleanupCanaries();

        /// <summary>Associates an exact owned path with an observation, without proving malware or the current file identity.</summary>
        bool IsCanaryPath(string path);
    }

    /// <summary>
    /// Creates decoys with CREATE_NEW and records their native volume/file identity for handle-specific cleanup.
    /// Path checks reject implicit remote/reparse targets but cannot guarantee race-free ancestor traversal.
    /// Ownership is memory-only: a new manager never adopts files left by an earlier process instance.
    /// </summary>
    public class CanaryTrapManager : ICanaryTrapManager
    {
        /// <summary>Primary decoy name; a matching name alone never establishes ownership.</summary>
        public const string CanaryFileName = "!_ultron_shield_canary.docx";

        /// <summary>Secondary decoy name; a matching name alone never establishes ownership.</summary>
        public const string SecondaryCanaryFileName = "~z_ultron_shield_canary.docx";

        /// <summary>Names attempted only with exclusive creation; existing files retain their content and attributes.</summary>
        public static readonly string[] CanaryFileNames = new[] { CanaryFileName, SecondaryCanaryFileName };

        private const string CanaryDecoyContent =
@"ULTRON DEFENDER - HARMLESS RANSOMWARE OBSERVER DECOY
This harmless decoy belongs to the Ultron user-mode ransomware observer.
Changes to the decoy may provide an alert for further investigation while the service is running.
An alert does not prove malware or confirm containment. There is no guaranteed reaction time,
no kernel pre-access enforcement, and no promise that other files cannot be changed first.
Keep Microsoft Defender enabled and maintain independent backups.";

        private const uint CreateNew = 1;
        private const uint OpenExisting = 3;
        private const uint ReadAttributes = 0x80;
        private const uint DeleteAccess = 0x10000;
        private const uint ReadWriteAccess = 0xC0000000;
        private readonly Dictionary<string, FileIdentity> _ownedCanaries = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _lock = new();
        private volatile bool _isCleaningUpCanaries;

        /// <summary>Number of owned path records, including deletion observations not yet reconciled.</summary>
        public int CanaryFileCount
        {
            get { lock (_lock) return _ownedCanaries.Count; }
        }

        /// <summary>Indicates handle-specific cleanup so observer callbacks can suppress manager-owned removals.</summary>
        public bool IsCleaningUpCanaries => _isCleaningUpCanaries;

        /// <summary>Returns a path snapshot; current identities are revalidated before redeployment or removal.</summary>
        public IReadOnlyList<string> CanaryFiles
        {
            get { lock (_lock) return _ownedCanaries.Keys.ToArray(); }
        }

        /// <summary>
        /// Creates harmless decoys only under eligible local roots. Repeated deployment preserves live identities,
        /// removes stale records and creates a fresh record only when CREATE_NEW succeeds. Null input is rejected;
        /// inaccessible targets are logged and skipped without modifying pre-existing files.
        /// </summary>
        public void DeployCanaries(IEnumerable<string> protectedDirs)
        {
            ArgumentNullException.ThrowIfNull(protectedDirs);
            lock (_lock)
            {
                foreach (var record in _ownedCanaries.ToArray())
                    if (!TryReadIdentity(record.Key, out var identity) || identity != record.Value)
                        _ownedCanaries.Remove(record.Key);

                foreach (string dir in protectedDirs)
                {
                    if (!ImplicitLocalPathPolicy.IsEligible(dir)) continue;
                    try
                    {
                        if (!Directory.Exists(dir)) continue;
                        foreach (string name in CanaryFileNames)
                        {
                            try
                            {
                                string path = NormalizeLocalPath(Path.Combine(dir, name));
                                if (!_ownedCanaries.ContainsKey(path) && ImplicitLocalPathPolicy.IsEligible(path))
                                    CreateCanary(path);
                            }
                            catch (IOException exception) when (exception.InnerException is Win32Exception { NativeErrorCode: 80 or 183 })
                            {
                                Trace.TraceInformation("Pre-existing file was not adopted as a canary: {0}", exception);
                            }
                            catch (Exception exception)
                            {
                                Trace.TraceWarning("Canary creation was skipped: {0}", exception);
                            }
                        }
                    }
                    catch (Exception exception)
                    {
                        Trace.TraceWarning("Canary deployment target was skipped: {0}", exception);
                    }
                }
            }
        }

        /// <summary>
        /// Removes an owned file only after local eligibility, final-path and native identity checks on the same
        /// delete-capable handle. Replacement files are neither changed nor deleted. Failed owned removals are
        /// logged and retained for a later retry; successful or obsolete records are removed.
        /// </summary>
        public void CleanupCanaries()
        {
            lock (_lock)
            {
                _isCleaningUpCanaries = true;
                try
                {
                    foreach (var record in _ownedCanaries.ToArray())
                        CleanupCanary(record.Key, record.Value);
                }
                finally { _isCleaningUpCanaries = false; }
            }
        }

        /// <summary>
        /// Matches only an exact normalized path recorded by successful creation, including a deleted/renamed
        /// decoy's old path until redeployment or cleanup. This is event association, not evidence about the current
        /// file or its actor; destructive cleanup independently requires a matching handle-bound identity.
        /// </summary>
        public bool IsCanaryPath(string path)
        {
            if (!ImplicitLocalPathPolicy.HasLocalSyntax(path)) return false;
            try
            {
                string normalized = NormalizeLocalPath(path);
                lock (_lock) return _ownedCanaries.ContainsKey(normalized);
            }
            catch (Exception exception)
            {
                Trace.TraceWarning("Canary observation path could not be normalized: {0}", exception);
                return false;
            }
        }

        private void CreateCanary(string path)
        {
            using SafeFileHandle handle = OpenHandle(path, ReadWriteAccess | DeleteAccess, CreateNew);
            FileIdentity? identity = null;
            FileStream? stream = null;
            try
            {
                identity = ReadIdentity(handle, path);
                stream = new FileStream(handle, FileAccess.ReadWrite, 4096);
                stream.Write(Encoding.UTF8.GetBytes(CanaryDecoyContent));
                stream.Flush();
                var attributes = new FileBasicInfo { Attributes = (uint)(FileAttributes.Hidden | FileAttributes.System) };
                if (!SetBasicInfo(handle, 0, ref attributes, (uint)Marshal.SizeOf<FileBasicInfo>()))
                    throw NativeFailure("Created canary attributes could not be set through its handle.");
                _ownedCanaries.Add(path, identity.Value);
            }
            catch (Exception exception)
            {
                Trace.TraceWarning("New canary initialization failed: {0}", exception);
                try { DeleteByHandle(handle); }
                catch (Exception cleanupException)
                {
                    Trace.TraceWarning("New canary rollback failed: {0}", cleanupException);
                    if (identity.HasValue) _ownedCanaries[path] = identity.Value;
                }
            }
            finally { stream?.Dispose(); }
        }

        private void CleanupCanary(string path, FileIdentity expected)
        {
            if (!ImplicitLocalPathPolicy.IsEligible(path))
            {
                _ownedCanaries.Remove(path);
                return;
            }
            try
            {
                using SafeFileHandle handle = OpenHandle(path, ReadAttributes | DeleteAccess, OpenExisting);
                if (ReadIdentity(handle, path) == expected) DeleteByHandle(handle);
                _ownedCanaries.Remove(path);
            }
            catch (Exception exception)
            {
                Trace.TraceWarning("Canary cleanup did not remove a file: {0}", exception);
                if (exception.InnerException is Win32Exception { NativeErrorCode: 2 or 3 })
                    _ownedCanaries.Remove(path);
            }
        }

        private static bool TryReadIdentity(string path, out FileIdentity identity)
        {
            identity = default;
            if (!ImplicitLocalPathPolicy.IsEligible(path)) return false;
            try
            {
                using SafeFileHandle handle = OpenHandle(path, ReadAttributes, OpenExisting);
                identity = ReadIdentity(handle, path);
                return true;
            }
            catch (Exception exception)
            {
                Trace.TraceWarning("Canary ownership could not be retained: {0}", exception);
                return false;
            }
        }

        private static SafeFileHandle OpenHandle(string path, uint access, uint disposition)
        {
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("Native canary ownership requires Windows.");
            string nativePath = path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path : @"\\?\" + path;
            // Share reads only and open the leaf itself: writers, replacement and reparse targets are excluded.
            SafeFileHandle handle = CreateFileW(nativePath, access, 1, IntPtr.Zero, disposition, 0x00200080, IntPtr.Zero);
            if (!handle.IsInvalid) return handle;
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("Canary file could not be opened with exclusive identity protection.", new Win32Exception(error));
        }

        private static FileIdentity ReadIdentity(SafeFileHandle handle, string expectedPath)
        {
            if (!GetFileInformationByHandle(handle, out var info))
                throw NativeFailure("Canary attributes could not be verified through its handle.");
            if ((info.Attributes & (uint)(FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
                throw new IOException("Canary handle refers to a reparse point or directory.");
            string finalPath = ReadFinalPath(handle, expectedPath.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase));
            if (!ImplicitLocalPathPolicy.IsEligible(finalPath) ||
                !string.Equals(finalPath, expectedPath, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Canary final path differs from its eligible local ownership path.");
            if (!GetFileIdInfo(handle, 18, out var fileId, (uint)Marshal.SizeOf<FileIdInfo>()))
                throw NativeFailure("Canary native volume/file identity could not be verified.");
            return new FileIdentity(fileId.VolumeSerialNumber, fileId.FileIdLow, fileId.FileIdHigh,
                info.CreationTimeLow, info.CreationTimeHigh);
        }

        private static string ReadFinalPath(SafeFileHandle handle, bool useVolumeGuid)
        {
            uint flags = useVolumeGuid ? 1u : 0u;
            var buffer = new StringBuilder(1024);
            uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, flags);
            if (length >= buffer.Capacity)
            {
                buffer = new StringBuilder(checked((int)length + 1));
                length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, flags);
            }
            if (length == 0 || length >= buffer.Capacity)
                throw NativeFailure("Canary final path could not be read through its handle.");
            return NormalizeLocalPath(buffer.ToString());
        }

        private static string NormalizeLocalPath(string path)
        {
            if (!ImplicitLocalPathPolicy.HasLocalSyntax(path))
                throw new ArgumentException("Canary paths must have unambiguous local storage syntax.", nameof(path));
            string normalized = Path.GetFullPath(path.Replace('/', '\\'));
            return normalized.StartsWith(@"\\?\", StringComparison.Ordinal) && normalized.Length > 5 && normalized[5] == ':'
                ? normalized[4..] : normalized;
        }

        private static void DeleteByHandle(SafeFileHandle handle)
        {
            uint flags = 0x11; // FILE_DISPOSITION_FLAG_DELETE | IGNORE_READONLY_ATTRIBUTE.
            if (SetDispositionEx(handle, 21, ref flags, sizeof(uint))) return;
            int error = Marshal.GetLastWin32Error();
            if (error is not (1 or 50 or 87))
                throw new IOException("Canary handle-specific deletion failed.", new Win32Exception(error));
            var disposition = new FileDispositionInfo { DeleteFile = true };
            if (!SetDisposition(handle, 4, ref disposition, (uint)Marshal.SizeOf<FileDispositionInfo>()))
                throw NativeFailure("Canary handle-specific deletion fallback failed.");
        }

        private static IOException NativeFailure(string message) => new(message, new Win32Exception(Marshal.GetLastWin32Error()));

        private readonly record struct FileIdentity(ulong VolumeSerialNumber, ulong FileIdLow, ulong FileIdHigh,
            uint CreationTimeLow, uint CreationTimeHigh);

        [StructLayout(LayoutKind.Sequential)]
        private struct FileIdInfo { public ulong VolumeSerialNumber; public ulong FileIdLow; public ulong FileIdHigh; }

        [StructLayout(LayoutKind.Sequential)]
        private struct HandleFileInformation
        {
            public uint Attributes;
            public uint CreationTimeLow; public uint CreationTimeHigh;
            public uint LastAccessTimeLow; public uint LastAccessTimeHigh;
            public uint LastWriteTimeLow; public uint LastWriteTimeHigh;
            public uint VolumeSerialNumber; public uint FileSizeHigh; public uint FileSizeLow;
            public uint NumberOfLinks; public uint FileIndexHigh; public uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileBasicInfo
        {
            public long CreationTime; public long LastAccessTime; public long LastWriteTime; public long ChangeTime;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileDispositionInfo { [MarshalAs(UnmanagedType.U1)] public bool DeleteFile; }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out HandleFileInformation info);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileIdInfo(SafeFileHandle handle, int infoClass, out FileIdInfo info, uint size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint size, uint flags);

        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetBasicInfo(SafeFileHandle handle, int infoClass, ref FileBasicInfo info, uint size);

        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetDisposition(SafeFileHandle handle, int infoClass, ref FileDispositionInfo info, uint size);

        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetDispositionEx(SafeFileHandle handle, int infoClass, ref uint flags, uint size);
    }
}
