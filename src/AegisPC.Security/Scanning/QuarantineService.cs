using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// AES-256 şifreli, Windows DPAPI donanım/kullanıcı korumalı, kalıcı meta veri indeksli ve güvenli geri yükleme/silme özellikli Karantina Kasası.
    /// </summary>
    public class QuarantineService : IQuarantineService
    {
        private readonly IHashService _hashService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger<QuarantineService>? _logger;
        private readonly string _quarantineDir;
        private readonly string _indexFilePath;
        private readonly string _vaultKeyFilePath;
        private readonly List<QuarantineEntry> _quarantinedItems = new();
        private readonly object _lock = new();

        private byte[]? _cachedMasterKey;
        private byte[]? _dpapiEntropy; // Generated per-installation, no longer hardcoded
        private static readonly byte[] LegacyFallbackKeySeed = SHA256.HashData(Encoding.UTF8.GetBytes(Environment.MachineName + "_Ultron_Quarantine_Vault_2026"));
        private const string QuarantineMagicHeader = "ULTRON_QUAR_V2";

        private readonly AegisPC.Contracts.Safety.IProtectedPathGuard _protectedPathGuard;
        private readonly AegisPC.Contracts.Safety.IReparsePointGuard _reparsePointGuard;

        public QuarantineService(
            IHashService hashService,
            IAuditLogService? auditLogService = null,
            ILogger<QuarantineService>? logger = null,
            string? customVaultDir = null,
            AegisPC.Contracts.Safety.IProtectedPathGuard? protectedPathGuard = null,
            AegisPC.Contracts.Safety.IReparsePointGuard? reparsePointGuard = null)
        {
            _hashService = hashService;
            _auditLogService = auditLogService;
            _logger = logger;
            _protectedPathGuard = protectedPathGuard ?? new AegisPC.Security.Safety.ProtectedPathGuard();
            _reparsePointGuard = reparsePointGuard ?? new AegisPC.Security.Safety.ReparsePointGuard();

            if (!string.IsNullOrEmpty(customVaultDir))
            {
                _quarantineDir = customVaultDir;
            }
            else
            {
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                _quarantineDir = Path.Combine(appData, "AegisPC", "QuarantineVault");
            }

            Directory.CreateDirectory(_quarantineDir);
            _indexFilePath = Path.Combine(_quarantineDir, "quarantine_index.json");
            _vaultKeyFilePath = Path.Combine(_quarantineDir, "vault.key");

            EnsureMasterKey();
            LoadIndexFromDisk();
        }

        private void EnsureMasterKey()
        {
            try
            {
                // Generate or load per-installation DPAPI entropy (not hardcoded)
                var entropyFilePath = Path.Combine(_quarantineDir, "entropy.dat");
                if (File.Exists(entropyFilePath))
                {
                    _dpapiEntropy = File.ReadAllBytes(entropyFilePath);
                }
                else
                {
                    _dpapiEntropy = new byte[32];
                    using var rng = RandomNumberGenerator.Create();
                    rng.GetBytes(_dpapiEntropy);
                    File.WriteAllBytes(entropyFilePath, _dpapiEntropy);
                    // Restrict file ACL (best effort)
                    try { File.SetAttributes(entropyFilePath, FileAttributes.Hidden | FileAttributes.System); } catch { }
                }

                if (File.Exists(_vaultKeyFilePath))
                {
                    var encryptedKey = File.ReadAllBytes(_vaultKeyFilePath);
                    _cachedMasterKey = ProtectedData.Unprotect(encryptedKey, _dpapiEntropy, DataProtectionScope.LocalMachine);
                }
                else
                {
                    // Generate fresh cryptographically random 256-bit AES master key
                    var newKey = new byte[32];
                    using var rng = RandomNumberGenerator.Create();
                    rng.GetBytes(newKey);

                    var encryptedKey = ProtectedData.Protect(newKey, _dpapiEntropy, DataProtectionScope.LocalMachine);
                    File.WriteAllBytes(_vaultKeyFilePath, encryptedKey);
                    _cachedMasterKey = newKey;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "DPAPI key generation failed, falling back to machine seed.");
                _cachedMasterKey = LegacyFallbackKeySeed;
            }
        }

        private byte[] GetMasterKey() => _cachedMasterKey ?? LegacyFallbackKeySeed;

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, int dwFlags);
        private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

        public async Task<bool> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return false;

            try
            {
                var eval = _protectedPathGuard.Evaluate(path);
                if (eval.IsProtected)
                {
                    _logger?.LogWarning("Attempted quarantine on protected system path blocked: {Path} ({Reason})", path, eval.Reason);
                    return false;
                }

                var reparse = _reparsePointGuard.Inspect(path);
                if (reparse.IsReparsePoint && (reparse.IsCrossBoundaryTrap || reparse.PointsToProtectedTarget))
                {
                    _reparsePointGuard.SafeDeleteLinkOnly(path);
                    _logger?.LogWarning("Symlink trap severed to protect target: {Path}", path);
                    return false;
                }

                var canonicalPath = Path.GetFullPath(path);
                var fileInfo = new FileInfo(canonicalPath);
                long originalFileSize = fileInfo.Length;
                string originalFileName = fileInfo.Name;

                int id;
                lock (_lock)
                {
                    id = _quarantinedItems.Count > 0 ? _quarantinedItems.Max(x => x.Id) + 1 : 1;
                }

                var quarantineFileName = $"vault_{id}_{Guid.NewGuid():N}.quar";
                var quarantineFilePath = Path.Combine(_quarantineDir, quarantineFileName);

                // 1. Encrypt with AES-256-CBC using DPAPI protected Master Key (Streaming — no full RAM load)
                using var aes = Aes.Create();
                aes.Key = GetMasterKey();
                aes.GenerateIV();
                var sha256 = await _hashService.ComputeSha256Async(canonicalPath, cancellationToken);

                // 2. Write Container (Magic + IV + SHA256 + Encrypted Data) via streaming
                using (var fsOut = new FileStream(quarantineFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var bw = new BinaryWriter(fsOut, Encoding.UTF8, leaveOpen: true))
                {
                    bw.Write(QuarantineMagicHeader);
                    bw.Write(aes.IV.Length);
                    bw.Write(aes.IV);
                    bw.Write(sha256);

                    // Placeholder for encrypted data length — will be patched after encryption
                    long encryptedLengthPosition = fsOut.Position;
                    bw.Write((int)0); // placeholder

                    long encryptedStartPosition = fsOut.Position;

                    using (var csEncrypt = new CryptoStream(fsOut, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
                    using (var fsRead = new FileStream(canonicalPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        await fsRead.CopyToAsync(csEncrypt, 81920, cancellationToken);
                    }

                    // Patch the encrypted data length
                    int encryptedLength = (int)(fsOut.Position - encryptedStartPosition);
                    fsOut.Position = encryptedLengthPosition;
                    bw.Write(encryptedLength);
                    fsOut.Position = fsOut.Length; // seek back to end
                }

                // 4. Terminate any running process locking the target file
                try
                {
                    var processes = Process.GetProcesses();
                    foreach (var proc in processes)
                    {
                        try
                        {
                            if (proc.Id <= 4) continue;
                            if (string.Equals(proc.MainModule?.FileName, canonicalPath, StringComparison.OrdinalIgnoreCase))
                            {
                                proc.Kill(entireProcessTree: true);
                            }
                        }
                        catch { }
                    }
                }
                catch { }

                // 5. Safely wipe original file attributes and delete/zero out
                bool deleted = false;
                for (int attempt = 0; attempt < 25; attempt++)
                {
                    try
                    {
                        File.SetAttributes(canonicalPath, FileAttributes.Normal);
                        File.Delete(canonicalPath);
                        deleted = true;
                        break;
                    }
                    catch
                    {
                        await Task.Delay(40, cancellationToken);
                    }
                }

                if (!deleted)
                {
                    try
                    {
                        // If delete was blocked by lingering handle, truncate file to 0 bytes
                        using (var fsTruncate = new FileStream(canonicalPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                        {
                            fsTruncate.SetLength(0);
                        }
                        File.Delete(canonicalPath);
                        deleted = true;
                    }
                    catch
                    {
                        try
                        {
                            MoveFileEx(canonicalPath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                        }
                        catch { }
                    }
                }

                var entry = new QuarantineEntry
                {
                    Id = id,
                    OriginalPath = canonicalPath,
                    QuarantinePath = quarantineFilePath,
                    FileName = originalFileName,
                    SHA256 = sha256,
                    FileSize = originalFileSize,
                    Reason = reason,
                    RiskLevel = RiskLevel.HighRisk,
                    QuarantinedAt = DateTime.UtcNow,
                    Status = QuarantineStatus.Quarantined
                };

                lock (_lock)
                {
                    _quarantinedItems.Add(entry);
                    SaveIndexToDisk();
                }

                _logger?.LogInformation("Quarantined file encrypted with DPAPI AES-256 to vault: {Path} -> {QuarPath}", canonicalPath, quarantineFilePath);

                if (_auditLogService != null)
                {
                    await _auditLogService.LogActionAsync(
                        AuditAction.FileQuarantined,
                        "File",
                        fileInfo.Name,
                        canonicalPath,
                        reason,
                        AuditResult.Success,
                        cancellationToken: cancellationToken);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to quarantine file: {Path}", path);
                return false;
            }
        }

        public Task<bool> RestoreFileAsync(int id, CancellationToken cancellationToken = default)
        {
            return RestoreFileAsync(id, null, cancellationToken);
        }

        public async Task<bool> RestoreFileAsync(int id, string? customDestinationPath, CancellationToken cancellationToken = default)
        {
            QuarantineEntry? entry;
            lock (_lock)
            {
                entry = _quarantinedItems.FirstOrDefault(x => x.Id == id && x.Status == QuarantineStatus.Quarantined);
            }

            if (entry == null)
            {
                _logger?.LogWarning("Quarantine restore failed: Entry {Id} not found.", id);
                return false;
            }

            if (!File.Exists(entry.QuarantinePath))
            {
                _logger?.LogWarning("Quarantine restore failed: Vault file missing on disk: {Path}", entry.QuarantinePath);
                return false;
            }

            try
            {
                var destination = string.IsNullOrWhiteSpace(customDestinationPath) ? entry.OriginalPath : customDestinationPath;
                var destDir = Path.GetDirectoryName(destination);
                if (destDir != null && !Directory.Exists(destDir))
                {
                    Directory.CreateDirectory(destDir);
                }

                // Decrypt container
                byte[] decryptedBytes = DecryptVaultContainer(entry.QuarantinePath);

                // Verify integrity
                using (var sha = SHA256.Create())
                {
                    var restoredHash = Convert.ToHexString(sha.ComputeHash(decryptedBytes));
                    if (!restoredHash.Equals(entry.SHA256, StringComparison.OrdinalIgnoreCase))
                    {
                        _logger?.LogError("Quarantine integrity check failed for {Id}. Hash mismatch.", id);
                        return false;
                    }
                }

                // Write restored file
                await File.WriteAllBytesAsync(destination, decryptedBytes, cancellationToken);

                // Safely remove vault container
                try { File.Delete(entry.QuarantinePath); } catch { }

                lock (_lock)
                {
                    entry.Status = QuarantineStatus.Restored;
                    entry.RestoredAt = DateTime.UtcNow;
                    SaveIndexToDisk();
                }

                _logger?.LogInformation("Quarantined file restored: {Id} -> {Dest}", id, destination);

                if (_auditLogService != null)
                {
                    await _auditLogService.LogActionAsync(
                        AuditAction.FileRestored,
                        "File",
                        entry.FileName,
                        destination,
                        "Dosya kullanıcı talebiyle karantinadan geri yüklendi.",
                        AuditResult.Success,
                        cancellationToken: cancellationToken);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to restore quarantine file {Id}", id);
                return false;
            }
        }

        public Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default)
        {
            QuarantineEntry? entry;
            lock (_lock)
            {
                entry = _quarantinedItems.FirstOrDefault(x => x.Id == id);
            }

            if (entry == null) return Task.FromResult(false);

            try
            {
                if (File.Exists(entry.QuarantinePath))
                {
                    // Overwrite before deleting (secure zero wipe)
                    var len = new FileInfo(entry.QuarantinePath).Length;
                    using (var fs = new FileStream(entry.QuarantinePath, FileMode.Open, FileAccess.Write))
                    {
                        byte[] zeroes = new byte[Math.Min(len, 4096)];
                        long written = 0;
                        while (written < len)
                        {
                            int toWrite = (int)Math.Min(zeroes.Length, len - written);
                            fs.Write(zeroes, 0, toWrite);
                            written += toWrite;
                        }
                    }
                    File.Delete(entry.QuarantinePath);
                }

                lock (_lock)
                {
                    entry.Status = QuarantineStatus.Deleted;
                    _quarantinedItems.Remove(entry);
                    SaveIndexToDisk();
                }

                _logger?.LogInformation("Quarantined file permanently wiped: {Id} ({FileName})", id, entry.FileName);

                if (_auditLogService != null)
                {
                    _ = _auditLogService.LogActionAsync(
                        AuditAction.FileDeleted,
                        "File",
                        entry.FileName,
                        entry.OriginalPath,
                        "Karantinadaki dosya kalıcı olarak silindi ve diski sıfırlandı.",
                        AuditResult.Success,
                        cancellationToken: cancellationToken);
                }

                return Task.FromResult(true);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to permanently delete quarantined item {Id}", id);
                return Task.FromResult(false);
            }
        }

        public Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var item = _quarantinedItems.FirstOrDefault(x => x.Id == id);
                return Task.FromResult(item);
            }
        }

        public Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                // Only return active quarantined items whose vault file actually exists on disk
                var validItems = _quarantinedItems
                    .Where(x => x.Status == QuarantineStatus.Quarantined && File.Exists(x.QuarantinePath))
                    .ToList();

                return Task.FromResult(validItems);
            }
        }

        private byte[] DecryptVaultContainer(string quarantineFilePath)
        {
            using var fs = new FileStream(quarantineFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var br = new BinaryReader(fs);

            var header = br.ReadString();
            if (header != QuarantineMagicHeader && header != "ULTRON_QUAR_V1")
            {
                throw new InvalidDataException("Invalid quarantine container header");
            }

            int ivLength = br.ReadInt32();
            byte[] iv = br.ReadBytes(ivLength);
            string originalSha = br.ReadString();
            int encLength = br.ReadInt32();
            byte[] encBytes = br.ReadBytes(encLength);

            // Attempt decryption with DPAPI Master Key first
            try
            {
                return DecryptWithKey(encBytes, GetMasterKey(), iv);
            }
            catch
            {
                // Fallback to legacy key seed for backward compatibility
                return DecryptWithKey(encBytes, LegacyFallbackKeySeed, iv);
            }
        }

        private static byte[] DecryptWithKey(byte[] encBytes, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            using var msDecrypt = new MemoryStream();
            using (var csDecrypt = new CryptoStream(new MemoryStream(encBytes), aes.CreateDecryptor(), CryptoStreamMode.Read))
            {
                csDecrypt.CopyTo(msDecrypt);
            }
            return msDecrypt.ToArray();
        }

        private void LoadIndexFromDisk()
        {
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_indexFilePath))
                    {
                        var json = File.ReadAllText(_indexFilePath);
                        var items = JsonSerializer.Deserialize<List<QuarantineEntry>>(json);
                        if (items != null)
                        {
                            _quarantinedItems.Clear();
                            _quarantinedItems.AddRange(items);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to load quarantine index from disk");
                }
            }
        }

        private void SaveIndexToDisk()
        {
            lock (_lock)
            {
                try
                {
                    var json = JsonSerializer.Serialize(_quarantinedItems, new JsonSerializerOptions { WriteIndented = true });
                    var tempFile = _indexFilePath + ".tmp." + Guid.NewGuid().ToString("N")[..8];
                    File.WriteAllText(tempFile, json);
                    File.Move(tempFile, _indexFilePath, overwrite: true);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to save quarantine index atomically to disk");
                }
            }
        }
    }
}
