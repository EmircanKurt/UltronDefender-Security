using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;

namespace AegisPC.Infrastructure.SecureStorage
{
    /// <summary>
    /// DPAPI based secure storage service.
    /// </summary>
    public class DpapiSecureStorageService : ISecureStorageService
    {
        private readonly string _secureStorageDir;
        private readonly byte[] _entropy = Encoding.UTF8.GetBytes("AegisPC_SecureStorage_Entropy_v1");

        public DpapiSecureStorageService()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            _secureStorageDir = Path.Combine(appData, "AegisPC", "secure");
            Directory.CreateDirectory(_secureStorageDir);
        }

        public async Task StoreSecretAsync(string key, string secret, CancellationToken cancellationToken = default)
        {
            var secretBytes = Encoding.UTF8.GetBytes(secret);
            var encryptedBytes = ProtectedData.Protect(secretBytes, _entropy, DataProtectionScope.CurrentUser);

            var filePath = GetFilePath(key);
            await File.WriteAllBytesAsync(filePath, encryptedBytes, cancellationToken);
        }

        public async Task<string?> GetSecretAsync(string key, CancellationToken cancellationToken = default)
        {
            var filePath = GetFilePath(key);
            if (!File.Exists(filePath))
            {
                return null;
            }

            var encryptedBytes = await File.ReadAllBytesAsync(filePath, cancellationToken);
            try
            {
                var secretBytes = ProtectedData.Unprotect(encryptedBytes, _entropy, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(secretBytes);
            }
            catch (CryptographicException)
            {
                return null;
            }
        }

        public Task DeleteSecretAsync(string key, CancellationToken cancellationToken = default)
        {
            var filePath = GetFilePath(key);
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
            return Task.CompletedTask;
        }

        private string GetFilePath(string key)
        {
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
            var hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            return Path.Combine(_secureStorageDir, $"{hashString}.dat");
        }
    }
}
