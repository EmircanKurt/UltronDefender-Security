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
            catch (IOException ex) when (ex.HResult == unchecked((int)0x800700E1) || ex.Message.Contains("virüs", StringComparison.OrdinalIgnoreCase) || ex.Message.Contains("virus", StringComparison.OrdinalIgnoreCase))
            {
                // Windows Win32 ERROR_VIRUS_INFECTED (0x800700E1): Dosya işletim sistemi/Defender tarafından virüs içerdiği gerekçesiyle kilitlendi
                return "VIRUS_INFECTED_OS_BLOCKED";
            }
            catch (Exception)
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
                var hashBytes = await SHA1.HashDataAsync(stream, cancellationToken);
                return Convert.ToHexString(hashBytes).ToLowerInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}
