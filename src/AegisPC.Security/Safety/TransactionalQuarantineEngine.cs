using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Safety
{
    /// <summary>
    /// Atomik, adımlı ve geri alınabilir (Transactional Rollback) Güvenli Karantina Motoru.
    /// Korumalı sistem dosyalarını, sembolik bağ tuzaklarını (Symlink LPE/DOS) ve dosya kilitlerini güvenle yönetir.
    /// </summary>
    public class TransactionalQuarantineEngine : ITransactionalQuarantine
    {
        private readonly ICanonicalPathResolver _pathResolver;
        private readonly IProtectedPathGuard _protectedPathGuard;
        private readonly IReparsePointGuard _reparsePointGuard;
        private readonly IHashService _hashService;
        private readonly ILogger<TransactionalQuarantineEngine>? _logger;

        private readonly string _vaultDir;
        private readonly string _indexFilePath;
        private readonly string _vaultKeyFilePath;
        private readonly List<QuarantineEntry> _quarantinedItems = new();
        private readonly object _lock = new();

        private byte[]? _cachedMasterKey;
        private static readonly byte[] DpapiEntropy = Encoding.UTF8.GetBytes("AegisPC_Transactional_Vault_DPAPI_2026");
        private static readonly byte[] FallbackSeed = SHA256.HashData(Encoding.UTF8.GetBytes(Environment.MachineName + "_AegisPC_Vault_Seed"));

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, int dwFlags);
        private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

        public TransactionalQuarantineEngine(
            ICanonicalPathResolver? pathResolver = null,
            IProtectedPathGuard? protectedPathGuard = null,
            IReparsePointGuard? reparsePointGuard = null,
            IHashService? hashService = null,
            string? customVaultDir = null,
            ILogger<TransactionalQuarantineEngine>? logger = null)
        {
            _pathResolver = pathResolver ?? new CanonicalPathResolver();
            _protectedPathGuard = protectedPathGuard ?? new ProtectedPathGuard(_pathResolver);
            _reparsePointGuard = reparsePointGuard ?? new ReparsePointGuard(_pathResolver, _protectedPathGuard);
            _hashService = hashService ?? new AegisPC.Security.Scanning.HashService();
            _logger = logger;

            if (!string.IsNullOrEmpty(customVaultDir))
            {
                _vaultDir = customVaultDir;
            }
            else
            {
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                _vaultDir = Path.Combine(appData, "AegisPC", "QuarantineVault");
            }

            Directory.CreateDirectory(_vaultDir);
            _indexFilePath = Path.Combine(_vaultDir, "quarantine_index.json");
            _vaultKeyFilePath = Path.Combine(_vaultDir, "vault.key");

            EnsureMasterKey();
            LoadIndex();
        }

        public async Task<QuarantineTransactionResult> ExecuteQuarantineAsync(QuarantineRequest request, CancellationToken cancellationToken = default)
        {
            var result = new QuarantineTransactionResult
            {
                Success = false,
                OriginalPath = request.TargetFilePath,
                Status = QuarantineTransactionStatus.NotStarted
            };

            if (string.IsNullOrWhiteSpace(request.TargetFilePath))
            {
                result.Status = QuarantineTransactionStatus.AbortedFileInaccessible;
                result.Message = "Dosya yolu boş veya geçersiz.";
                return result;
            }

            // 1. AŞAMA: Kanonikleştirme & Pre-flight Denetimi
            var canonicalPath = _pathResolver.Resolve(request.TargetFilePath);
            result.CanonicalPath = canonicalPath;
            result.AuditSteps.Add($"1. Yol kanonikleştirildi: '{canonicalPath}'");

            // 2. AŞAMA: Korumalı Sistem Yolu Muhafızı (Protected Path Guard)
            var protectedEval = _protectedPathGuard.Evaluate(canonicalPath);
            if (protectedEval.IsProtected)
            {
                result.Status = QuarantineTransactionStatus.AbortedProtectedPath;
                result.Message = $"Korumalı Sistem Dosyası: {protectedEval.Reason}";
                result.AuditSteps.Add($"2. Korumalı yol engeli: {protectedEval.Reason}");
                return result;
            }

            // 3. AŞAMA: Reparse Point (Symlink / Junction) Tuzağı Denetimi
            var reparseInfo = _reparsePointGuard.Inspect(canonicalPath);
            if (reparseInfo.IsReparsePoint)
            {
                result.AuditSteps.Add($"3. Reparse Point tespit edildi (Tür: {reparseInfo.Type}, Hedef: '{reparseInfo.TargetPath}')");

                if (reparseInfo.IsCrossBoundaryTrap || reparseInfo.PointsToProtectedTarget)
                {
                    // LPE Tuzağı: Antivirüs korunan sistem dosyasını silmesin diye sadece bağı sil!
                    _reparsePointGuard.SafeDeleteLinkOnly(canonicalPath);
                    result.Status = QuarantineTransactionStatus.AbortedReparsePointTrap;
                    result.Message = $"Güvenlik Tuzağı Engellendi: '{canonicalPath}' korunan bir sistem hedefini ({reparseInfo.TargetPath}) işaret eden sembolik bağdır. Hedefe dokunulmadan bağ güvenle silindi.";
                    result.AuditSteps.Add("Reparse Point bağı güvenle kaldırıldı, hedef korundu.");
                    return result;
                }
            }

            if (!File.Exists(canonicalPath) && !Directory.Exists(canonicalPath))
            {
                result.Status = QuarantineTransactionStatus.AbortedFileInaccessible;
                result.Message = $"Fiziksel dosya bulunamadı: '{canonicalPath}'";
                return result;
            }

            result.Status = QuarantineTransactionStatus.PreFlightPassed;
            result.AuditSteps.Add("Pre-Flight güvenlik denetimleri başarıyla geçildi.");

            // 4. AŞAMA: Dosyayı Açık Tutan Süreçleri Sonlandırma
            if (request.ForceKillHoldingProcesses)
            {
                KillHoldingProcesses(canonicalPath, result.AuditSteps);
                result.Status = QuarantineTransactionStatus.ProcessesTerminated;
            }

            // 5. AŞAMA: AES-256 Şifreli Kasa Hazırlığı (Transactional Vault Staging)
            string stagingVaultPath = string.Empty;
            int newId;
            lock (_lock)
            {
                newId = _quarantinedItems.Count > 0 ? _quarantinedItems.Max(x => x.Id) + 1 : 1;
            }
            result.QuarantineId = newId;

            var finalVaultFileName = $"vault_{newId}_{Guid.NewGuid():N}.quar";
            var finalVaultFilePath = Path.Combine(_vaultDir, finalVaultFileName);
            stagingVaultPath = finalVaultFilePath + ".tmp";

            try
            {
                var fileInfo = new FileInfo(canonicalPath);
                long originalSize = fileInfo.Length;
                string sha256 = await _hashService.ComputeSha256Async(canonicalPath, cancellationToken);
                result.SHA256 = sha256;

                byte[] rawBytes;
                await using (var fs = new FileStream(canonicalPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 8192, useAsync: true))
                {
                    rawBytes = new byte[fs.Length];
                    int read = await fs.ReadAsync(rawBytes.AsMemory(0, (int)fs.Length), cancellationToken);
                    if (read < rawBytes.Length)
                    {
                        Array.Resize(ref rawBytes, read);
                    }
                }

                // AES-256 Şifreleme
                var masterKey = GetMasterKey();
                var iv = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(iv);
                }

                byte[] cipherBytes;
                using (var aes = Aes.Create())
                {
                    aes.Key = masterKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using var encryptor = aes.CreateEncryptor();
                    cipherBytes = encryptor.TransformFinalBlock(rawBytes, 0, rawBytes.Length);
                }

                // Staging Kasa Dosyasına Yaz
                await using (var outFs = new FileStream(stagingVaultPath, FileMode.Create, FileAccess.Write, FileShare.None, 8192, useAsync: true))
                await using (var bw = new BinaryWriter(outFs, Encoding.UTF8, leaveOpen: false))
                {
                    bw.Write(Encoding.ASCII.GetBytes("AEGIS_VAULT_V3"));
                    bw.Write((int)3); // Version 3
                    bw.Write(iv.Length);
                    bw.Write(iv);
                    bw.Write(rawBytes.Length); // Original Plaintext Length
                    bw.Write(cipherBytes.Length);
                    bw.Write(cipherBytes);
                }

                // Atomic Rename from .tmp to final .quar
                File.Move(stagingVaultPath, finalVaultFilePath, overwrite: true);
                result.VaultContainerPath = finalVaultFilePath;
                result.Status = QuarantineTransactionStatus.VaultStagingCompleted;
                result.AuditSteps.Add($"4. Dosya şifrelendi ve kasaya güvenle yazıldı: '{finalVaultFileName}'");

                // 6. AŞAMA: Orijinal Dosyanın Güvenli Silinmesi / İmhası
                bool originalDeleted = false;
                try
                {
                    File.SetAttributes(canonicalPath, FileAttributes.Normal);
                    
                    if (request.WipeOriginalPayloadBytes && originalSize > 0 && originalSize < 50 * 1024 * 1024)
                    {
                        // Üzerine sıfır yazarak güvenli imha
                        try
                        {
                            await using var wipeFs = new FileStream(canonicalPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                            byte[] zeros = new byte[Math.Min(65536, originalSize)];
                            long written = 0;
                            while (written < originalSize)
                            {
                                int chunk = (int)Math.Min(zeros.Length, originalSize - written);
                                await wipeFs.WriteAsync(zeros.AsMemory(0, chunk), cancellationToken);
                                written += chunk;
                            }
                            await wipeFs.FlushAsync(cancellationToken);
                        }
                        catch { }
                    }

                    for (int attempt = 0; attempt < 10; attempt++)
                    {
                        try
                        {
                            File.Delete(canonicalPath);
                            originalDeleted = !File.Exists(canonicalPath);
                            if (originalDeleted) break;
                        }
                        catch
                        {
                            await Task.Delay(100, cancellationToken);
                        }
                    }

                    if (!originalDeleted && File.Exists(canonicalPath))
                    {
                        // Kilitli dosya için yeniden başlatmada silme emri
                        MoveFileEx(canonicalPath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                        result.AuditSteps.Add("Orijinal dosya kilitli olduğu için bir sonraki Windows açılışında silinmek üzere zamanlandı (MoveFileEx).");
                    }
                    else
                    {
                        result.Status = QuarantineTransactionStatus.OriginalFileRemoved;
                        result.AuditSteps.Add("5. Orijinal tehdit dosyası diskten tamamen kaldırıldı.");
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Could not delete original file immediately on '{Path}'", canonicalPath);
                }

                // 7. AŞAMA: Transaction Commit
                var entry = new QuarantineEntry
                {
                    Id = newId,
                    OriginalPath = canonicalPath,
                    FileName = Path.GetFileName(canonicalPath),
                    QuarantinePath = finalVaultFilePath,
                    Reason = request.ThreatReason,
                    SHA256 = sha256,
                    FileSize = originalSize,
                    QuarantinedAt = DateTime.UtcNow,
                    Status = AegisPC.Core.Enums.QuarantineStatus.Quarantined
                };

                lock (_lock)
                {
                    _quarantinedItems.Add(entry);
                    SaveIndex();
                }

                result.Success = true;
                result.Status = QuarantineTransactionStatus.Committed;
                result.Message = $"Dosya başarıyla karantinaya alındı (ID: {newId}).";
                result.AuditSteps.Add("6. Karantina işlemi başarıyla onaylandı (Transaction Committed).");
                return result;
            }
            catch (Exception ex)
            {
                // ROLLBACK: Staging dosyasını temizle, orijinal dosyaya dokunma!
                try
                {
                    if (File.Exists(stagingVaultPath)) File.Delete(stagingVaultPath);
                    if (File.Exists(finalVaultFilePath)) File.Delete(finalVaultFilePath);
                }
                catch { }

                result.Status = QuarantineTransactionStatus.RolledBack;
                result.Message = $"Karantina işlemi hata nedeniyle geri alındı (Rollback): {ex.Message}";
                result.AuditSteps.Add($"HATA: {ex.Message}. Karantina işlemi geri alındı, orijinal dosya korundu.");
                _logger?.LogError(ex, "Quarantine transaction rolled back for '{Path}'", canonicalPath);
                return result;
            }
        }

        public async Task<QuarantineRestoreResult> ExecuteRestoreAsync(int quarantineId, string? targetOverride = null, CancellationToken cancellationToken = default)
        {
            var result = new QuarantineRestoreResult { Success = false, QuarantineId = quarantineId };

            QuarantineEntry? entry;
            lock (_lock)
            {
                entry = _quarantinedItems.Find(x => x.Id == quarantineId);
            }

            if (entry == null)
            {
                result.Message = $"Karantina kaydı bulunamadı (ID: {quarantineId}).";
                return result;
            }

            var destPath = string.IsNullOrWhiteSpace(targetOverride) ? entry.OriginalPath : targetOverride;

            if (!File.Exists(entry.QuarantinePath))
            {
                result.Message = $"Karantina kasa dosyası bulunamadı: '{entry.QuarantinePath}'";
                return result;
            }

            try
            {
                byte[] rawPlaintext;
                await using (var fs = new FileStream(entry.QuarantinePath, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, useAsync: true))
                using (var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: false))
                {
                    var headerBytes = br.ReadBytes(14);
                    var header = Encoding.ASCII.GetString(headerBytes);
                    int version = br.ReadInt32();

                    int ivLen = br.ReadInt32();
                    var iv = br.ReadBytes(ivLen);

                    int plainLen = br.ReadInt32();
                    int cipherLen = br.ReadInt32();
                    var cipherBytes = br.ReadBytes(cipherLen);

                    var masterKey = GetMasterKey();
                    using var aes = Aes.Create();
                    aes.Key = masterKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using var decryptor = aes.CreateDecryptor();
                    rawPlaintext = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                }

                var destDir = Path.GetDirectoryName(destPath);
                if (!string.IsNullOrEmpty(destDir))
                {
                    Directory.CreateDirectory(destDir);
                }

                await File.WriteAllBytesAsync(destPath, rawPlaintext, cancellationToken);
                result.Success = true;
                result.RestoredPath = destPath;
                result.Message = $"Dosya başarıyla geri yüklendi: '{destPath}'";

                lock (_lock)
                {
                    entry.Status = AegisPC.Core.Enums.QuarantineStatus.Restored;
                    entry.RestoredAt = DateTime.UtcNow;
                    SaveIndex();
                }

                return result;
            }
            catch (Exception ex)
            {
                result.Message = $"Geri yükleme başarısız: {ex.Message}";
                _logger?.LogError(ex, "Failed to restore quarantine item {Id}", quarantineId);
                return result;
            }
        }

        private static void KillHoldingProcesses(string filePath, List<string> audit)
        {
            try
            {
                var fileName = Path.GetFileName(filePath);
                var procs = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(fileName));
                foreach (var p in procs)
                {
                    try
                    {
                        if (string.Equals(p.MainModule?.FileName, filePath, StringComparison.OrdinalIgnoreCase))
                        {
                            p.Kill(entireProcessTree: true);
                            p.WaitForExit(1000);
                            audit.Add($"Dosyayı çalıştıran süreç sonlandırıldı (PID: {p.Id}, Ad: {p.ProcessName}).");
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void EnsureMasterKey()
        {
            try
            {
                if (File.Exists(_vaultKeyFilePath))
                {
                    var encryptedKey = File.ReadAllBytes(_vaultKeyFilePath);
                    _cachedMasterKey = ProtectedData.Unprotect(encryptedKey, DpapiEntropy, DataProtectionScope.LocalMachine);
                }
                else
                {
                    var newKey = new byte[32];
                    using var rng = RandomNumberGenerator.Create();
                    rng.GetBytes(newKey);

                    var encryptedKey = ProtectedData.Protect(newKey, DpapiEntropy, DataProtectionScope.LocalMachine);
                    File.WriteAllBytes(_vaultKeyFilePath, encryptedKey);
                    _cachedMasterKey = newKey;
                }
            }
            catch
            {
                _cachedMasterKey = FallbackSeed;
            }
        }

        private byte[] GetMasterKey() => _cachedMasterKey ?? FallbackSeed;

        private void LoadIndex()
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
            catch { }
        }

        private void SaveIndex()
        {
            try
            {
                var json = JsonSerializer.Serialize(_quarantinedItems, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_indexFilePath, json);
            }
            catch { }
        }
    }
}
