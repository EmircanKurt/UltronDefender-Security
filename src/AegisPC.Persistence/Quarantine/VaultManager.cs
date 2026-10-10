using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AegisPC.Persistence.Quarantine
{
    public class QuarantineVaultMetadata
    {
        public string OriginalPath { get; set; } = string.Empty;
        public string SHA256 { get; set; } = string.Empty;
        public DateTime QuarantinedAtUtc { get; set; } = DateTime.UtcNow;
        public string ThreatName { get; set; } = string.Empty;
    }

    public static class SecureQuarantineVault
    {
        private static byte[]? _masterKey;
        private static readonly string VaultKeyPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AegisPC", "SecureVault", "vault_master.key");

        private static byte[] GetMasterKey()
        {
            if (_masterKey != null) return _masterKey;

            var dir = Path.GetDirectoryName(VaultKeyPath)!;
            Directory.CreateDirectory(dir);

            if (File.Exists(VaultKeyPath))
            {
                var encryptedKey = File.ReadAllBytes(VaultKeyPath);
                _masterKey = System.Security.Cryptography.ProtectedData.Unprotect(
                    encryptedKey, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
            }
            else
            {
                _masterKey = new byte[32];
                RandomNumberGenerator.Fill(_masterKey);
                var encryptedKey = System.Security.Cryptography.ProtectedData.Protect(
                    _masterKey, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
                File.WriteAllBytes(VaultKeyPath, encryptedKey);
                try { File.SetAttributes(VaultKeyPath, FileAttributes.Hidden | FileAttributes.System); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine($"[Vault] Kasa anahtar dosyası gizli/sistem olarak işaretlenemedi: {ex.Message}"); }
            }

            return _masterKey;
        }

        public static void QuarantineFile(string sourceFilePath, string vaultTargetPath, QuarantineVaultMetadata meta)
        {
            if (!File.Exists(sourceFilePath)) return;

            var fileInfo = new FileInfo(sourceFilePath);
            if (fileInfo.Length > 50 * 1024 * 1024)
            {
                throw new InvalidOperationException("Dosya boyutu doğrudan bellek içi karantina kasası sınırını (50MB) aşıyor. Büyük dosyalar için TransactionalQuarantineEngine kullanılmalıdır.");
            }

            byte[] fileBytes = File.ReadAllBytes(sourceFilePath);
            string metaJson = JsonSerializer.Serialize(meta);
            byte[] metaBytes = Encoding.UTF8.GetBytes(metaJson);

            using var ms = new MemoryStream();
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(metaBytes.Length);
                bw.Write(metaBytes);
                bw.Write(fileBytes.Length);
                bw.Write(fileBytes);
            }

            byte[] plainData = ms.ToArray();
            byte[] nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);
            byte[] tag = new byte[16];
            byte[] cipherText = new byte[plainData.Length];

            using (var aesGcm = new AesGcm(GetMasterKey(), 16))
            {
                aesGcm.Encrypt(nonce, plainData, cipherText, tag);
            }

            var dir = Path.GetDirectoryName(vaultTargetPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            using (var fs = new FileStream(vaultTargetPath, FileMode.Create, FileAccess.Write))
            {
                fs.Write(nonce);
                fs.Write(tag);
                fs.Write(cipherText);
            }

            try 
            {
                File.SetAttributes(sourceFilePath, FileAttributes.Normal);
                File.Delete(sourceFilePath); 
            } 
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"[Vault] Kaynak dosya karantinaya alındı ancak orijinal dosya silinemedi: {sourceFilePath} ({ex.Message})");
            }
        }

        public static (bool Success, QuarantineVaultMetadata? Metadata, byte[]? FileBytes) RestoreFile(string vaultFilePath)
        {
            if (!File.Exists(vaultFilePath)) return (false, null, null);

            try
            {
                byte[] raw = File.ReadAllBytes(vaultFilePath);
                if (raw.Length < 28) return (false, null, null); // 12 nonce + 16 tag

                byte[] nonce = new byte[12];
                byte[] tag = new byte[16];
                byte[] cipherText = new byte[raw.Length - 28];

                Buffer.BlockCopy(raw, 0, nonce, 0, 12);
                Buffer.BlockCopy(raw, 12, tag, 0, 16);
                Buffer.BlockCopy(raw, 28, cipherText, 0, cipherText.Length);

                byte[] plainData = new byte[cipherText.Length];
                using (var aesGcm = new AesGcm(GetMasterKey(), 16))
                {
                    aesGcm.Decrypt(nonce, cipherText, tag, plainData);
                }

                using var ms = new MemoryStream(plainData);
                using var br = new BinaryReader(ms);

                int metaLen = br.ReadInt32();
                byte[] metaBytes = br.ReadBytes(metaLen);
                int fileLen = br.ReadInt32();
                byte[] fileBytes = br.ReadBytes(fileLen);

                string metaJson = Encoding.UTF8.GetString(metaBytes);
                var meta = JsonSerializer.Deserialize<QuarantineVaultMetadata>(metaJson);

                return (true, meta, fileBytes);
            }
            catch
            {
                return (false, null, null);
            }
        }
    }
}
