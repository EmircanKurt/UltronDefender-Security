using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Exceptions;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Safety
{
    /// <summary>
    /// SQLite tabanlı, WAL modunda çalışan, ACID işlem garantili ve güvenli geri yükleme/silme özellikli Karantina Motoru.
    /// Korumalı sistem dosyalarını, sembolik bağ tuzaklarını (Symlink LPE/DOS) ve dosya kilitlerini güvenle yönetir.
    /// </summary>
    public class TransactionalQuarantineEngine : ITransactionalQuarantine, IDisposable
    {
        private readonly ICanonicalPathResolver _pathResolver;
        private readonly IProtectedPathGuard _protectedPathGuard;
        private readonly IReparsePointGuard _reparsePointGuard;
        private readonly IHashService _hashService;
        private readonly ILogger<TransactionalQuarantineEngine>? _logger;

        private readonly string _vaultDir;
        private readonly string _vaultKeyFilePath;
        private readonly QuarantineVaultDatabase _database;

        private byte[]? _cachedMasterKey;
        private static readonly byte[] LegacyDpapiEntropy = Encoding.UTF8.GetBytes("AegisPC_Transactional_Vault_DPAPI_2026");

        public QuarantineVaultDatabase Database => _database;
        public string VaultDirectory => _vaultDir;

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
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _vaultDir = Path.Combine(programData, "UltronDefender", "QuarantineVault");
            }

            Directory.CreateDirectory(_vaultDir);
            EnsureVaultSecurity(_vaultDir);

            _vaultKeyFilePath = Path.Combine(_vaultDir, "vault.key");
            EnsureMasterKey();
            // A damaged or inaccessible key must stop construction before metadata migration.
            _database = new QuarantineVaultDatabase(_vaultDir, _logger);
        }

        private void EnsureVaultSecurity(string vaultDir)
        {
            if (!OperatingSystem.IsWindows()) return;
            try
            {
                var dirInfo = new DirectoryInfo(vaultDir);
                var dirSecurity = dirInfo.GetAccessControl();

                var adminSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                var systemSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                var currentUser = System.Security.Principal.WindowsIdentity.GetCurrent().User;

                dirSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                dirSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    systemSid, System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));

                dirSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    adminSid, System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));

                if (currentUser != null && !currentUser.Equals(adminSid) && !currentUser.Equals(systemSid))
                {
                    dirSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                        currentUser, System.Security.AccessControl.FileSystemRights.FullControl,
                        System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                        System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                }

                dirInfo.SetAccessControl(dirSecurity);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Could not set strict ACL on vault directory {VaultDir}", vaultDir);
            }
        }

        public byte[] GetMasterKey() => _cachedMasterKey != null ? (byte[])_cachedMasterKey.Clone() : throw new QuarantineException("Kasa anahtarı yüklenemedi (Fail-Closed).");

        private void EnsureMasterKey()
        {
            // Cross-process initialization lock: never publish a second key over an existing vault.
            using var mutex = new Mutex(false, "Local\\AegisVaultKey_" + Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(_vaultDir).ToUpperInvariant()))));
            bool acquired = false;
            try
            {
                try { acquired = mutex.WaitOne(TimeSpan.FromSeconds(30)); }
                catch (AbandonedMutexException) { acquired = true; }
                if (!acquired) throw new IOException("Kasa anahtarı kilidi alınamadı.");
                // A file lock also serializes service/UI initialization across Windows sessions.
                using var initializationLock = AcquireInitializationLock();
                var entropyPath = Path.Combine(_vaultDir, "vault_entropy.dat");
                var oldEntropyPath = Path.Combine(_vaultDir, "entropy.dat");
                if (File.Exists(_vaultKeyFilePath))
                {
                    var encrypted = File.ReadAllBytes(_vaultKeyFilePath);
                    var candidates = new List<byte[]>();
                    if (File.Exists(entropyPath)) candidates.Add(File.ReadAllBytes(entropyPath));
                    if (File.Exists(oldEntropyPath)) candidates.Add(File.ReadAllBytes(oldEntropyPath));
                    candidates.Add(LegacyDpapiEntropy);
                    foreach (var entropy in candidates)
                    foreach (var scope in new[] { DataProtectionScope.LocalMachine, DataProtectionScope.CurrentUser })
                    {
                        try
                        {
                            var key = ProtectedData.Unprotect(encrypted, entropy, scope);
                            if (key.Length != 32) throw new CryptographicException("Invalid vault key length.");
                            _cachedMasterKey = key;
                            // Existing key/entropy pairs remain untouched, including old layouts.
                            return;
                        }
                        catch (CryptographicException) { }
                    }
                    throw new CryptographicException("Mevcut kasa anahtarı çözülemedi; anahtar değiştirilmedi (Fail-Closed).");
                }
                if (Directory.GetFiles(_vaultDir, "*.quar").Length > 0)
                    throw new CryptographicException("Dolu kasanın anahtarı eksik; yeni anahtar oluşturulmadı.");

                byte[] newEntropy = File.Exists(entropyPath) ? File.ReadAllBytes(entropyPath) : RandomNumberGenerator.GetBytes(32);
                if (!File.Exists(entropyPath)) WriteDurableNewFile(entropyPath, newEntropy);
                byte[] newKey = RandomNumberGenerator.GetBytes(32);
                var protectedKey = ProtectedData.Protect(newKey, newEntropy, DataProtectionScope.LocalMachine);
                WriteDurableNewFile(_vaultKeyFilePath, protectedKey);
                _cachedMasterKey = newKey;
            }
            catch (Exception ex) when (ex is not CryptographicException)
            {
                throw new QuarantineException("Kasa anahtarı yüklenemedi; işlem güvenle durduruldu.", ex);
            }
            finally { if (acquired) mutex.ReleaseMutex(); }
        }

        private static void WriteDurableNewFile(string path, byte[] bytes)
        {
            string staging = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(staging, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(bytes);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(staging, path, overwrite: false);
            }
            finally { if (File.Exists(staging)) File.Delete(staging); }
        }

        private FileStream AcquireInitializationLock()
        {
            var timer = Stopwatch.StartNew();
            while (true)
            {
                try
                {
                    return new FileStream(Path.Combine(_vaultDir, "vault.init.lock"), FileMode.OpenOrCreate,
                        FileAccess.ReadWrite, FileShare.None);
                }
                catch (IOException) when (timer.Elapsed < TimeSpan.FromSeconds(30))
                { Thread.Sleep(25); }
            }
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
            if (request.ExpectedSha256 != null &&
                (request.ExpectedSha256.Length != 64 || !System.Linq.Enumerable.All(request.ExpectedSha256, Uri.IsHexDigit)))
            {
                result.Status = QuarantineTransactionStatus.AbortedFileInaccessible;
                result.Message = "Geçerli tespit SHA-256 değeri olmadan otomatik karantina uygulanmadı.";
                return result;
            }

            // 1. AŞAMA: Kanonikleştirme & Pre-flight Denetimi
            var canonicalPath = _pathResolver.Resolve(request.TargetFilePath);
            result.CanonicalPath = canonicalPath;
            result.AuditSteps.Add($"1. Yol kanonikleştirildi: '{canonicalPath}'");

            // Eşzamanlı işlem kilidi: Aynı dosya için mükerrer yarış durumlarını engeller
            var pathLock = _database.GetPathLock(canonicalPath);
            await pathLock.WaitAsync(cancellationToken);

            try
            {
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
                        if (request.ExpectedSha256 == null) _reparsePointGuard.SafeDeleteLinkOnly(canonicalPath);
                        result.Status = QuarantineTransactionStatus.AbortedReparsePointTrap;
                        result.Message = "Reparse point güvenlik tuzağı engellendi; otomatik işlem hedefe dokunmadı.";
                        result.AuditSteps.Add("Protected reparse target was not modified.");
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
                if (request.ForceKillHoldingProcesses && request.ExpectedSha256 == null)
                {
                    KillHoldingProcesses(canonicalPath, result.AuditSteps);
                    result.Status = QuarantineTransactionStatus.ProcessesTerminated;
                }

                // 5. AŞAMA: AES-256 Şifreli Kasa Hazırlığı (doğrulanabilir V4 formatı)
                int newId = _database.AllocateNextId();
                result.QuarantineId = newId;

                var finalVaultFileName = $"vault_{newId}_{Guid.NewGuid():N}.quar";
                var finalVaultFilePath = Path.Combine(_vaultDir, finalVaultFileName);
                var stagingVaultPath = finalVaultFilePath + ".tmp";
                QuarantineEntry? pendingEntry = null;
                bool indexPersisted = false;
                bool originalRemovalCommitted = false;

                try
                {
                    using var source = new QuarantineSourceHandle(canonicalPath);
                    if (!string.Equals(source.FinalPath, canonicalPath, StringComparison.OrdinalIgnoreCase))
                        throw new IOException("Kaynak yolu güvenlik denetiminden sonra değişti; dosyaya dokunulmadı.");
                    // 1) Kasa dosyasını oluştur ve doğrula
                    var (plainSize, sha256) = await VaultContainerCodec.EncryptToVaultV4Async(
                        source.Stream, stagingVaultPath, GetMasterKey(), cancellationToken);

                    result.SHA256 = sha256;
                    if (request.ExpectedSha256 != null && !string.Equals(sha256, request.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                        throw new IOException("Dosya tespitten sonra değişti; kaynak korunarak karantina iptal edildi.");

                    // Staging dosyasının sağlamlığını doğrula
                    var stagingInfo = new FileInfo(stagingVaultPath);
                    if (!stagingInfo.Exists || stagingInfo.Length == 0)
                    {
                        throw new InvalidOperationException("Kasa staging dosyası oluşturulamadı veya boş yazıldı.");
                    }

                    // Atomik taşıma: .tmp -> .quar
                    File.Move(stagingVaultPath, finalVaultFilePath, overwrite: true);
                    // Read back and verify the only recovery copy before removing the source.
                    // Keep its identity protected through the database and deletion commit.
                    using var vaultReadGuard = new FileStream(finalVaultFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                    using (var verificationHash = SHA256.Create())
                    await using (var hashOutput = new CryptoStream(Stream.Null, verificationHash, CryptoStreamMode.Write, leaveOpen: true))
                    {
                        if (!await VaultContainerCodec.DecryptVaultStreamAsync(finalVaultFilePath, hashOutput, GetMasterKey(), cancellationToken))
                            throw new CryptographicException("Kasa geri okuma doğrulaması başarısız.");
                        await hashOutput.FlushFinalBlockAsync(cancellationToken);
                        if (!string.Equals(Convert.ToHexString(verificationHash.Hash!), sha256, StringComparison.OrdinalIgnoreCase))
                            throw new CryptographicException("Kasa geri okuma SHA-256 doğrulaması başarısız.");
                    }
                    result.VaultContainerPath = finalVaultFilePath;
                    result.Status = QuarantineTransactionStatus.VaultStagingCompleted;
                    result.AuditSteps.Add($"4. Dosya doğrulanabilir V4 formatında şifrelendi ve kasaya yazıldı: '{finalVaultFileName}'");

                    // 2) SADECE KASA DOĞRULANDIKTAN SONRA: SQLite indeksini yaz ve onayla (ACID Transaction)
                    pendingEntry = new QuarantineEntry
                    {
                        Id = newId,
                        OriginalPath = canonicalPath,
                        FileName = Path.GetFileName(canonicalPath),
                        QuarantinePath = finalVaultFilePath,
                        Reason = request.ThreatReason,
                        SHA256 = sha256,
                        FileSize = plainSize,
                        RiskLevel = ResolveRiskLevel(request.DetectionEvidence, sha256),
                        QuarantinedAt = DateTime.UtcNow,
                        Status = QuarantineStatus.Quarantined
                    };
                    result.AuditSteps.Add($"Structured detection risk: {pendingEntry.RiskLevel}.");

                    await _database.InsertEntryAsync(pendingEntry, canonicalPath, cancellationToken);
                    indexPersisted = true;
                    result.AuditSteps.Add("5. Karantina kaydı SQLite veritabanına ACID işlemle yazıldı.");

                    // 3) SADECE VE SADECE BUNDAN SONRA: Kaynak dosyayı sil/sıfırla
                    try
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        source.MarkForDeletion();
                        originalRemovalCommitted = true;
                        source.Dispose();

                        result.Status = QuarantineTransactionStatus.OriginalFileRemoved;
                        result.AuditSteps.Add("6. Orijinal tehdit dosyası diskten tamamen kaldırıldı.");
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning(ex, "Could not delete original file on '{Path}'", canonicalPath);
                        throw;
                    }

                    // 4) Transaction Commit & Başarı
                    result.Success = true;
                    result.Status = QuarantineTransactionStatus.Committed;
                    result.Message = $"Dosya başarıyla karantinaya alındı (ID: {newId}).";
                    result.AuditSteps.Add("7. Karantina işlemi başarıyla onaylandı (Transaction Committed).");
                    return result;
                }
                catch (Exception ex)
                {
                    if (originalRemovalCommitted)
                    {
                        // A post-commit reporting error must never destroy the sole recovery copy.
                        result.Success = true;
                        result.Status = QuarantineTransactionStatus.Committed;
                        result.Message = $"Dosya kasada korundu (ID: {newId}); işlem sonrası bildirim hatası: {ex.Message}";
                        _logger?.LogWarning(ex, "Quarantine committed; recovery copy retained after reporting failure.");
                        return result;
                    }
                    // Rollback Adımı:
                    // Eğer indeks yazılamadıysa veya kaynak dosya silinemezse:
                    // Orijinal dosya ASLA silinmiş olarak raporlanmaz, kasa dosyası temizlenir.
                    if (indexPersisted && pendingEntry != null)
                    {
                        try
                        {
                            // Kaynak dosya silinemediği için durumu PartialFailed yap veya kaydı geri al
                            await _database.RemoveEntryAsync(pendingEntry.Id, CancellationToken.None);
                            indexPersisted = false;
                        }
                        catch (Exception dbEx)
                        {
                            _logger?.LogError(dbEx, "Failed to remove entry on rollback for ID {Id}", pendingEntry.Id);
                        }
                    }

                    try
                    {
                        if (File.Exists(stagingVaultPath)) File.Delete(stagingVaultPath);
                        // Keep the recoverable payload if database compensation fails.
                        if (!indexPersisted && File.Exists(finalVaultFilePath)) File.Delete(finalVaultFilePath);
                    }
                    catch (Exception cleanupEx)
                    {
                        _logger?.LogWarning(cleanupEx, "Rollback sırasında kasa dosyası temizleme başarısız.");
                    }

                    result.Success = false;
                    result.Status = QuarantineTransactionStatus.RolledBack;
                    result.Message = $"Karantina işlemi hata nedeniyle geri alındı (Rollback): {ex.Message}";
                    result.AuditSteps.Add($"HATA: {ex.Message}. Karantina işlemi geri alındı, orijinal dosya korundu.");
                    _logger?.LogError(ex, "Quarantine transaction rolled back for '{Path}'", canonicalPath);
                    return result;
                }
            }
            finally
            {
                pathLock.Release();
            }
        }

        public async Task<QuarantineRestoreResult> ExecuteRestoreAsync(int quarantineId, string? targetOverride = null, CancellationToken cancellationToken = default)
        {
            var gate = _database.GetPathLock(Path.GetFullPath(_vaultDir) + "|entry|" + quarantineId);
            await gate.WaitAsync(cancellationToken);
            try { return await ExecuteRestoreCoreAsync(quarantineId, targetOverride, cancellationToken); }
            finally { gate.Release(); }
        }

        private async Task<QuarantineRestoreResult> ExecuteRestoreCoreAsync(int quarantineId, string? targetOverride, CancellationToken cancellationToken)
        {
            var result = new QuarantineRestoreResult { Success = false, QuarantineId = quarantineId };
            string? stagingRestorePath = null;

            var entry = await _database.GetEntryByIdAsync(quarantineId, cancellationToken);
            if (entry == null)
            {
                result.Message = $"Karantina kaydı bulunamadı (ID: {quarantineId}).";
                return result;
            }
            if (entry.Status != QuarantineStatus.Quarantined && entry.Status != QuarantineStatus.PartialFailed)
            {
                result.Message = "Kasa kaydı aktif karantinada değil; geri yükleme tekrarlanmadı.";
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
                // 1. GÜVENLİK: Korumalı Sistem Yolu Muhafızı (Protected Path Guard)
                var canonicalDestPath = _pathResolver.Resolve(destPath);
                destPath = canonicalDestPath;
                var protectedEval = _protectedPathGuard.Evaluate(canonicalDestPath);
                if (protectedEval.IsProtected)
                {
                    result.Message = $"Geri yükleme engellendi: Hedef korunan sistem yoludur ({protectedEval.Reason}). Yol: '{canonicalDestPath}'";
                    _logger?.LogWarning("Restore blocked: target path is protected by system policy: {Path}. Reason: {Reason}", canonicalDestPath, protectedEval.Reason);
                    return result;
                }

                // 2. GÜVENLİK: Hedef zaten varsa üzerine sessizce yazma
                if (File.Exists(destPath))
                {
                    // Dosya kilitli mi kontrolü
                    try
                    {
                        using var testStream = new FileStream(destPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    }
                    catch (IOException)
                    {
                        result.Message = "Hedef dosya başka bir program tarafından kullanılıyor (dosya kullanımda / kilitli).";
                        return result;
                    }

                    result.Message = "Geri yükleme hedefi zaten var; mevcut dosyanın üzerine yazılmadı.";
                    return result;
                }

                if (Directory.Exists(destPath))
                {
                    result.Message = "Geri yükleme hedefi zaten var; mevcut dizinin üzerine yazılamaz.";
                    return result;
                }

                var destDir = Path.GetDirectoryName(canonicalDestPath);
                if (!string.IsNullOrEmpty(destDir))
                {
                    Directory.CreateDirectory(destDir);
                }

                // 3. GÜVENLİK: Restore öncesi hedef yolda Symlink/Junction/Reparse Point kontrolü
                if (_reparsePointGuard != null)
                {
                    if (!string.IsNullOrEmpty(destDir))
                    {
                        var dirReparseInfo = _reparsePointGuard.Inspect(destDir);
                        if (dirReparseInfo.IsReparsePoint)
                        {
                            result.Message = $"Geri yükleme engellendi: Hedef dizin bir {dirReparseInfo.Type} (hedef: {dirReparseInfo.TargetPath}). Yol: '{destDir}'";
                            return result;
                        }
                    }
                }

                // 4. Akış halinde şifre çözme: .restore.tmp dosyasına atomik yazım
                stagingRestorePath = destPath + "." + Guid.NewGuid().ToString("N") + ".restore.tmp";

                bool decrypted = false;
                await using (var outFs = new FileStream(stagingRestorePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true))
                {
                    decrypted = await VaultContainerCodec.DecryptVaultStreamAsync(
                        entry.QuarantinePath, outFs, GetMasterKey(), cancellationToken);
                }

                if (!decrypted)
                {
                    await _database.UpdateStatusAsync(entry.Id, QuarantineStatus.Corrupted, cancellationToken: cancellationToken);
                    result.Message = "Kasa kaydı bozuk veya şifre çözülemedi.";
                    return result;
                }

                // 5. Bütünlük doğrulaması (SHA-256)
                var restoredHash = await _hashService.ComputeSha256Async(stagingRestorePath, cancellationToken);
                if (!string.IsNullOrWhiteSpace(entry.SHA256) && !string.Equals(restoredHash, entry.SHA256, StringComparison.OrdinalIgnoreCase))
                {
                    await _database.UpdateStatusAsync(entry.Id, QuarantineStatus.Corrupted, cancellationToken: cancellationToken);
                    result.Message = "Kasa kaydı bozuk (bütünlük doğrulaması/hash uyuşmazlığı).";
                    return result;
                }

                cancellationToken.ThrowIfCancellationRequested();

                // 6. Atomik Takas: staging dosyasını hedef yola taşı
                File.Move(stagingRestorePath, destPath, overwrite: false);

                // 7. Veritabanı durumunu güncelle
                // Publication is already committed. Caller cancellation must not interrupt bookkeeping.
                await _database.UpdateStatusAsync(entry.Id, QuarantineStatus.Restored, DateTime.UtcNow, CancellationToken.None);

                result.Success = true;
                result.RestoredPath = destPath;
                result.Message = $"Dosya başarıyla geri yüklendi: '{destPath}'";
                return result;
            }
            catch (Exception ex)
            {
                result.Message = $"Geri yükleme başarısız: {ex.Message}";
                _logger?.LogError(ex, "Failed to restore quarantine item {Id}", quarantineId);
                return result;
            }
            finally
            {
                try
                {
                    if (stagingRestorePath != null && File.Exists(stagingRestorePath))
                        File.Delete(stagingRestorePath);
                }
                catch { }
            }
        }

        public Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken cancellationToken = default)
        {
            return _database.GetActiveQuarantinedAsync(cancellationToken);
        }

        public Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken cancellationToken = default)
        {
            return _database.GetEntryByIdAsync(id, cancellationToken);
        }

        public async Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default)
        {
            var gate = _database.GetPathLock(Path.GetFullPath(_vaultDir) + "|entry|" + id);
            await gate.WaitAsync(cancellationToken);
            try { return await DeleteQuarantinedCoreAsync(id, cancellationToken); }
            finally { gate.Release(); }
        }

        private async Task<bool> DeleteQuarantinedCoreAsync(int id, CancellationToken cancellationToken)
        {
            var entry = await _database.GetEntryByIdAsync(id, cancellationToken);
            if (entry == null) return false;

            try
            {
                if (File.Exists(entry.QuarantinePath))
                {
                    // Kriptografik imha (shred): Dosyayı sıfırlarla ezerek sil
                    try
                    {
                        var length = new FileInfo(entry.QuarantinePath).Length;
                        await using (var fs = new FileStream(entry.QuarantinePath, FileMode.Open, FileAccess.Write, FileShare.None))
                        {
                            byte[] zeros = new byte[Math.Min(81920, length)];
                            long written = 0;
                            while (written < length)
                            {
                                int toWrite = (int)Math.Min(zeros.Length, length - written);
                                await fs.WriteAsync(zeros.AsMemory(0, toWrite), cancellationToken);
                                written += toWrite;
                            }
                            await fs.FlushAsync(cancellationToken);
                        }
                    }
                    catch { }

                    File.Delete(entry.QuarantinePath);
                }

                await _database.UpdateStatusAsync(id, QuarantineStatus.Deleted, cancellationToken: cancellationToken);
                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to shred/delete quarantine file {Path}", entry.QuarantinePath);
                return false;
            }
        }

        private static void KillHoldingProcesses(string filePath, List<string> audit)
        {
            try
            {
                var fileName = Path.GetFileName(filePath);
                var procs = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(fileName));
                string[] criticalProcesses = { "svchost", "csrss", "smss", "lsass", "wininit", "services", "System", "winlogon", "dwm" };

                foreach (var p in procs)
                {
                    try
                    {
                        if (Array.Exists(criticalProcesses, cp => string.Equals(cp, p.ProcessName, StringComparison.OrdinalIgnoreCase)))
                        {
                            audit.Add($"Kritik sistem süreci atlandı (PID: {p.Id}, Ad: {p.ProcessName}).");
                            continue;
                        }

                        var moduleFileName = p.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(moduleFileName) &&
                            (moduleFileName.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase) ||
                             moduleFileName.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase)))
                        {
                            audit.Add($"Sistem dizinindeki süreç atlandı (PID: {p.Id}, Ad: {p.ProcessName}).");
                            continue;
                        }

                        if (string.Equals(moduleFileName, filePath, StringComparison.OrdinalIgnoreCase))
                        {
                            p.Kill(entireProcessTree: true);
                            p.WaitForExit(1000);
                            audit.Add($"Dosyayı çalıştıran süreç sonlandırıldı (PID: {p.Id}, Ad: {p.ProcessName}).");
                        }
                    }
                    catch (Exception ex)
                    {
                        audit.Add($"Süreç sonlandırma hatası (PID: {p.Id}): {ex.Message}");
                    }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                audit.Add($"Süreç arama hatası: {ex.Message}");
            }
        }

        public void Dispose()
        {
            _database?.Dispose();
        }

        private RiskLevel ResolveRiskLevel(QuarantineDetectionEvidence? evidence, string actualSha256)
        {
            try
            {
                // The vault's read-back hash is the content identity; a caller cannot invent
                // a confirmed verdict merely by setting a display reason or evidence enum.
                if (AegisPC.Security.Scanning.MalwareSignatureDatabase.IsTrustedEmbeddedHash(actualSha256))
                    return RiskLevel.ConfirmedMalicious;
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Known-malware hash verification failed; quarantine risk remains unknown.");
            }

            if (evidence == null) return RiskLevel.Unknown;

            var evidenceHash = evidence.ContentSha256;
            if (evidenceHash is not { Length: 64 } ||
                !System.Linq.Enumerable.All(evidenceHash, Uri.IsHexDigit) ||
                !string.Equals(evidenceHash, actualSha256, StringComparison.OrdinalIgnoreCase))
            {
                _logger?.LogWarning("Quarantine risk evidence was not bound to the contained content; risk remains unknown.");
                return RiskLevel.Unknown;
            }

            if (evidence.Kind != QuarantineDetectionEvidenceKind.None)
                _logger?.LogWarning("Quarantine evidence kind {Kind} could not be independently verified; risk remains unknown.", evidence.Kind);
            return RiskLevel.Unknown;
        }
    }
}
