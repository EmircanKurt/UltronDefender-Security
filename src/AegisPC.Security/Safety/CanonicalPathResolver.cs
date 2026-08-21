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
    /// Windows dosya yollarını (8.3 kısa adlar, sembolik bağlar, cihaz önekleri, göreli yollar)
    /// deterministik ve mutlak fiziksel dosya yoluna dönüştüren kanonikleştirici.
    /// </summary>
    public class CanonicalPathResolver : ICanonicalPathResolver
    {
        private readonly ILogger<CanonicalPathResolver>? _logger;

        private const uint FILE_READ_ATTRIBUTES = 0x0080;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint VOLUME_NAME_DOS = 0x0;
        private const uint FILE_NAME_NORMALIZED = 0x0;

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetFinalPathNameByHandle(
            SafeFileHandle hFile,
            [Out] StringBuilder lpszFilePath,
            uint cchFilePath,
            uint dwFlags);

        public CanonicalPathResolver(ILogger<CanonicalPathResolver>? logger = null)
        {
            _logger = logger;
        }

        public string Resolve(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            try
            {
                // 1. Temel normalizasyon (Slashes, Trim, Redundant dots)
                var cleaned = path.Trim().Replace('/', '\\');

                // 2. Eğer dosya/dizin fiziksel olarak mevcutsa Win32 GetFinalPathNameByHandle ile gerçek yolu al
                if (File.Exists(cleaned) || Directory.Exists(cleaned))
                {
                    var resolvedFromHandle = GetFinalPathName(cleaned);
                    if (!string.IsNullOrEmpty(resolvedFromHandle))
                    {
                        return StripDevicePrefix(resolvedFromHandle);
                    }
                }

                // 3. Fallback: Path.GetFullPath ile normalize et
                var fullPath = Path.GetFullPath(cleaned);
                return StripDevicePrefix(fullPath);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Canonicalization fallback for '{Path}'", path);
                try
                {
                    return Path.GetFullPath(path.Trim());
                }
                catch
                {
                    return path;
                }
            }
        }

        public bool AreSamePhysicalFile(string path1, string path2)
        {
            if (string.IsNullOrWhiteSpace(path1) || string.IsNullOrWhiteSpace(path2)) return false;

            var resolved1 = Resolve(path1);
            var resolved2 = Resolve(path2);

            return string.Equals(resolved1, resolved2, StringComparison.OrdinalIgnoreCase);
        }

        private string? GetFinalPathName(string path)
        {
            try
            {
                using var handle = CreateFile(
                    path,
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    IntPtr.Zero);

                if (handle.IsInvalid)
                {
                    return null;
                }

                var sb = new StringBuilder(1024);
                uint res = GetFinalPathNameByHandle(handle, sb, (uint)sb.Capacity, VOLUME_NAME_DOS | FILE_NAME_NORMALIZED);
                if (res == 0)
                {
                    return null;
                }

                return sb.ToString();
            }
            catch
            {
                return null;
            }
        }

        private static string StripDevicePrefix(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return path;

            // "\\?\" veya "\??\" veya "\\.\" öneklerini temizle
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
            {
                return path[4..];
            }
            if (path.StartsWith(@"\??\", StringComparison.Ordinal))
            {
                return path[4..];
            }
            if (path.StartsWith(@"\\.\", StringComparison.Ordinal))
            {
                return path[4..];
            }

            return path;
        }
    }
}
