using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using AegisPC.Contracts.Safety;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Security.Safety
{
    /// <summary>
    /// Sembolik bağlar (Symlinks) ve NTFS Kavşak Noktalarını (Junctions) denetleyen,
    /// antivirüsün korunan sistem dosyalarını yanlışlıkla silmesini engelleyen güvenlik muhafızı.
    /// </summary>
    public class ReparsePointGuard : IReparsePointGuard
    {
        private readonly ICanonicalPathResolver _pathResolver;
        private readonly IProtectedPathGuard _protectedPathGuard;
        private readonly ILogger<ReparsePointGuard>? _logger;

        private const uint FSCTL_GET_REPARSE_POINT = 0x000900A8;
        private const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;
        private const uint IO_REPARSE_TAG_SYMLINK = 0xA000000C;
        private const uint IO_REPARSE_TAG_APPEXECLINK = 0x8000001B;

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            byte[] lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool DeleteFile(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool RemoveDirectory(string lpPathName);

        public ReparsePointGuard(
            ICanonicalPathResolver? pathResolver = null,
            IProtectedPathGuard? protectedPathGuard = null,
            ILogger<ReparsePointGuard>? logger = null)
        {
            _pathResolver = pathResolver ?? new CanonicalPathResolver();
            _protectedPathGuard = protectedPathGuard ?? new ProtectedPathGuard(_pathResolver);
            _logger = logger;
        }

        public ReparsePointInfo Inspect(string path)
        {
            var info = new ReparsePointInfo
            {
                Path = path,
                IsReparsePoint = false,
                Type = ReparsePointType.None
            };

            if (string.IsNullOrWhiteSpace(path)) return info;

            try
            {
                var resolved = _pathResolver.Resolve(path);

                // 1. Temel Öznitelik Kontrolü
                FileAttributes attrs = 0;
                if (File.Exists(path))
                {
                    attrs = File.GetAttributes(path);
                }
                else if (Directory.Exists(path))
                {
                    attrs = File.GetAttributes(path);
                }
                else
                {
                    return info;
                }

                if (!attrs.HasFlag(FileAttributes.ReparsePoint))
                {
                    return info;
                }

                info.IsReparsePoint = true;

                // 2. Win32 DeviceIoControl ile Reparse Tag ve Hedef Bilgisini Oku
                using var handle = CreateFile(
                    path,
                    0, // Query access
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                    IntPtr.Zero);

                if (!handle.IsInvalid)
                {
                    byte[] outBuffer = new byte[16384];
                    if (DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, IntPtr.Zero, 0, outBuffer, (uint)outBuffer.Length, out uint bytesReturned, IntPtr.Zero) && bytesReturned > 8)
                    {
                        uint reparseTag = BitConverter.ToUInt32(outBuffer, 0);

                        if (reparseTag == IO_REPARSE_TAG_MOUNT_POINT)
                        {
                            info.Type = ReparsePointType.MountPointOrJunction;
                            ushort substituteNameOffset = BitConverter.ToUInt16(outBuffer, 8);
                            ushort substituteNameLength = BitConverter.ToUInt16(outBuffer, 10);
                            ushort printNameOffset = BitConverter.ToUInt16(outBuffer, 12);
                            ushort printNameLength = BitConverter.ToUInt16(outBuffer, 14);

                            if (substituteNameLength > 0 && 16 + substituteNameOffset + substituteNameLength <= bytesReturned)
                            {
                                var subName = Encoding.Unicode.GetString(outBuffer, 16 + substituteNameOffset, substituteNameLength);
                                info.TargetPath = CleanReparseTarget(subName);
                            }
                            if (printNameLength > 0 && 16 + printNameOffset + printNameLength <= bytesReturned)
                            {
                                info.PrintName = Encoding.Unicode.GetString(outBuffer, 16 + printNameOffset, printNameLength);
                            }
                        }
                        else if (reparseTag == IO_REPARSE_TAG_SYMLINK)
                        {
                            info.Type = ReparsePointType.SymbolicLink;
                            ushort substituteNameOffset = BitConverter.ToUInt16(outBuffer, 8);
                            ushort substituteNameLength = BitConverter.ToUInt16(outBuffer, 10);
                            ushort printNameOffset = BitConverter.ToUInt16(outBuffer, 12);
                            ushort printNameLength = BitConverter.ToUInt16(outBuffer, 14);

                            if (substituteNameLength > 0 && 20 + substituteNameOffset + substituteNameLength <= bytesReturned)
                            {
                                var subName = Encoding.Unicode.GetString(outBuffer, 20 + substituteNameOffset, substituteNameLength);
                                info.TargetPath = CleanReparseTarget(subName);
                            }
                            if (printNameLength > 0 && 20 + printNameOffset + printNameLength <= bytesReturned)
                            {
                                info.PrintName = Encoding.Unicode.GetString(outBuffer, 20 + printNameOffset, printNameLength);
                            }
                        }
                        else if (reparseTag == IO_REPARSE_TAG_APPEXECLINK)
                        {
                            info.Type = ReparsePointType.AppExecLink;
                        }
                        else
                        {
                            info.Type = ReparsePointType.OtherReparsePoint;
                        }
                    }
                }

                // 3. Hedef yol korumalı mı kontrol et
                if (!string.IsNullOrEmpty(info.TargetPath))
                {
                    info.PointsToProtectedTarget = _protectedPathGuard.IsProtected(info.TargetPath);

                    // Eğer kullanıcı/temp alanındaki bir bağ, Windows sistem alanını hedefliyorsa bu bir tuzaktır (LPE Trap)
                    bool linkIsInUserSpace = !path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase);
                    if (linkIsInUserSpace && info.PointsToProtectedTarget)
                    {
                        info.IsCrossBoundaryTrap = true;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Reparse point analysis failed on '{Path}'", path);
            }

            return info;
        }

        public bool SafeDeleteLinkOnly(string linkPath)
        {
            if (string.IsNullOrWhiteSpace(linkPath)) return false;

            try
            {
                var attrs = File.GetAttributes(linkPath);
                if (!attrs.HasFlag(FileAttributes.ReparsePoint))
                {
                    return false; // Reparse point değilse bu metotla silinmez
                }

                if (attrs.HasFlag(FileAttributes.Directory))
                {
                    // Junction / Directory Symlink silme
                    return RemoveDirectory(linkPath);
                }
                else
                {
                    // File Symlink silme
                    return DeleteFile(linkPath);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to safely remove reparse point '{Path}'", linkPath);
                return false;
            }
        }

        private static string CleanReparseTarget(string target)
        {
            if (string.IsNullOrWhiteSpace(target)) return target;

            if (target.StartsWith(@"\??\", StringComparison.Ordinal))
            {
                return target[4..];
            }
            if (target.StartsWith(@"\\?\", StringComparison.Ordinal))
            {
                return target[4..];
            }

            return target;
        }
    }
}
