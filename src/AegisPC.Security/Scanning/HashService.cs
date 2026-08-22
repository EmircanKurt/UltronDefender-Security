using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;

namespace AegisPC.Security.Scanning
{
    public class HashService : IHashService
    {
        // 64 KB buffer — standart I/O performansı için optimal boyut
        // (önceki 8 KB buffer, büyük dosyalarda 8× fazla syscall yapıyordu)
        private const int BufferSize = 65536;

        public async Task<string> ComputeSha256Async(string filePath, CancellationToken cancellationToken = default)
        {
            if (!File.Exists(filePath)) return string.Empty;

            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, BufferSize,
                    FileOptions.SequentialScan | FileOptions.Asynchronous);
                var hashBytes = await SHA256.HashDataAsync(stream, cancellationToken);
                return Convert.ToHexString(hashBytes).ToLowerInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }

        public async Task<string> ComputeSha1Async(string filePath, CancellationToken cancellationToken = default)
        {
            if (!File.Exists(filePath)) return string.Empty;

            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, BufferSize,
                    FileOptions.SequentialScan | FileOptions.Asynchronous);
                using var sha1 = SHA1.Create();
                var hashBytes = await sha1.ComputeHashAsync(stream, cancellationToken);
                return Convert.ToHexString(hashBytes).ToLowerInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}
