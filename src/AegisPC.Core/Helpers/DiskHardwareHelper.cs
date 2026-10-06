using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Core.Helpers
{
    /// <summary>
    /// Disk depolama biriminin Katı Hal Sürücüsü (SSD / NVMe) mi yoksa
    /// mekanik dönen disk (HDD) mi olduğunu 0.1 milisaniyede Win32 IOCTL ile sorgulayan donanım yardımcısı.
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

        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> _driveSsdCache = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Sürücünün SSD mi olduğunu doğrular.
        /// IncursSeekPenalty == false -> SSD / NVMe (Paralel worker havuzu ölçeklendirilebilir)
        /// IncursSeekPenalty == true  -> Mekanik HDD (Kafa atlamalarını önlemek için sıralı/az iş parçacığı kullanılmalıdır)
        /// </summary>
        public static bool IsSolidStateDrive(string? pathOrDrive)
        {
            if (string.IsNullOrWhiteSpace(pathOrDrive)) return false;

            try
            {
                string root = Path.GetPathRoot(Path.GetFullPath(pathOrDrive)) ?? string.Empty;
                if (root.StartsWith(@"\\", StringComparison.Ordinal)) return false;
                string driveLetter = root.TrimEnd('\\'); // e.g. "C:"

                if (string.IsNullOrEmpty(driveLetter) || !driveLetter.Contains(':'))
                {
                    return false;
                }

                if (_driveSsdCache.TryGetValue(driveLetter, out bool isSsd))
                {
                    return isSsd;
                }

                string volumeDevicePath = @"\\.\" + driveLetter;
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
                    return false; // Unknown storage: do not assume high parallelism is safe.
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
                    out _,
                    IntPtr.Zero);

                if (success && result.Size >= Marshal.SizeOf<DEVICE_SEEK_PENALTY_DESCRIPTOR>())
                {
                    bool ssd = !result.IncursSeekPenalty;
                    _driveSsdCache[driveLetter] = ssd;
                    return ssd;
                }
            }
            catch { }

            return false; // Unknown storage uses the conservative seek-penalty policy.
        }
    }
}
