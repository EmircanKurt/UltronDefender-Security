using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Core.Helpers
{
    /// <summary>
    /// Queries the storage seek characteristic with read-only Win32 IOCTL; access failures remain Unknown.
    /// </summary>
    public static class DiskHardwareHelper
    {
        private const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
        private const int StorageDeviceSeekPenaltyProperty = 7;
        private const int PropertyStandardQuery = 0;

        [StructLayout(LayoutKind.Sequential)]
        private struct STORAGE_PROPERTY_QUERY
        {
            public int PropertyId;
            public int QueryType;
            public byte AdditionalParameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DEVICE_SEEK_PENALTY_DESCRIPTOR
        {
            public int Version;
            public int Size;
            [MarshalAs(UnmanagedType.I1)]
            public bool IncursSeekPenalty;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            ref STORAGE_PROPERTY_QUERY lpInBuffer,
            int nInBufferSize,
            out DEVICE_SEEK_PENALTY_DESCRIPTOR lpOutBuffer,
            int nOutBufferSize,
            out int lpBytesReturned,
            IntPtr lpOverlapped);

        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, StorageSeekKind> _driveSsdCache = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Represents a measured seek characteristic; Unknown is not a proven rotating disk or SSD.</summary>
        public enum StorageSeekKind { Unknown, Rotating, SolidState }

        /// <summary>Resolves only drive-letter or canonical volume-GUID device roots; UNC and arbitrary devices are rejected.</summary>
        public static string? ResolveVolumeDevicePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return null;
            if (path.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase))
            {
                int end = path.IndexOf('}');
                if (end != 47 || !Guid.TryParseExact(path.Substring(11, 36), "D", out _)) return null;
                if (path.Length > 48 && path[48] != '\\') return null;
                return path[..48];
            }
            if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.Length < 2 || path[1] != ':' || !char.IsAsciiLetter(path[0])) return null;
            if (path.Length > 2 && path[2] != '\\' && path[2] != '/') return null;
            return @"\\.\" + char.ToUpperInvariant(path[0]) + ":";
        }

        /// <summary>
        /// Sürücünün SSD mi olduğunu doğrular.
        /// IncursSeekPenalty == false -> SSD / NVMe (Paralel worker havuzu ölçeklendirilebilir)
        /// IncursSeekPenalty == true  -> Mekanik HDD (Kafa atlamalarını önlemek için sıralı/az iş parçacığı kullanılmalıdır)
        /// </summary>
        public static bool IsSolidStateDrive(string? pathOrDrive)
            => GetSeekKind(pathOrDrive) == StorageSeekKind.SolidState;

        /// <summary>Queries storage without writing it; unavailable measurements remain Unknown and are not cached permanently.</summary>
        public static StorageSeekKind GetSeekKind(string? pathOrDrive)
        {
            string? volumeDevicePath = ResolveVolumeDevicePath(pathOrDrive);
            if (volumeDevicePath == null || !OperatingSystem.IsWindows()) return StorageSeekKind.Unknown;

            try
            {
                if (_driveSsdCache.TryGetValue(volumeDevicePath, out var kind))
                {
                    return kind;
                }
                using var handle = CreateFile(
                    volumeDevicePath,
                    0, // Query access
                    1 | 2, // FILE_SHARE_READ | FILE_SHARE_WRITE
                    IntPtr.Zero,
                    3, // OPEN_EXISTING
                    0x80, // FILE_ATTRIBUTE_NORMAL
                    IntPtr.Zero);

                if (handle.IsInvalid)
                {
                    return StorageSeekKind.Unknown;
                }

                var query = new STORAGE_PROPERTY_QUERY
                {
                    PropertyId = StorageDeviceSeekPenaltyProperty,
                    QueryType = PropertyStandardQuery
                };

                bool success = DeviceIoControl(
                    handle,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    ref query,
                    Marshal.SizeOf<STORAGE_PROPERTY_QUERY>(),
                    out DEVICE_SEEK_PENALTY_DESCRIPTOR result,
                    Marshal.SizeOf<DEVICE_SEEK_PENALTY_DESCRIPTOR>(),
                    out int returned,
                    IntPtr.Zero);

                if (success && returned >= Marshal.SizeOf<DEVICE_SEEK_PENALTY_DESCRIPTOR>() && result.Size >= Marshal.SizeOf<DEVICE_SEEK_PENALTY_DESCRIPTOR>())
                {
                    var observed = result.IncursSeekPenalty ? StorageSeekKind.Rotating : StorageSeekKind.SolidState;
                    _driveSsdCache[volumeDevicePath] = observed;
                    return observed;
                }
            }
            catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
            { System.Diagnostics.Debug.WriteLine("Storage seek measurement unavailable: " + exception.GetType().Name); }

            return StorageSeekKind.Unknown;
        }
    }
}
