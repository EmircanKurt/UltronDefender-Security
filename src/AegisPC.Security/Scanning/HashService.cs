using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;

namespace AegisPC.Security.Scanning
{
    public class HashService : IHashService
    {
        public async Task<string> ComputeSha256Async(string filePath, CancellationToken cancellationToken = default)
        {
            if (!File.Exists(filePath)) return string.Empty;

            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 8192, useAsync: true);
                using var sha256 = SHA256.Create();
                var hashBytes = await sha256.ComputeHashAsync(stream, cancellationToken);
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
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 8192, useAsync: true);
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
