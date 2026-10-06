using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Safety;

/// <summary>Separates recovery and compatibility persistence from the containment transaction.</summary>
public partial class TransactionalQuarantineEngine
{
        /// <summary>Trusted internal recovery API; IPC callers must use authenticated streaming recovery instead of SYSTEM destination I/O.</summary>
        public async Task<QuarantineRestoreResult> ExecuteRestoreAsync(int quarantineId, string? targetOverride = null, CancellationToken cancellationToken = default)
        {
            using var operation = await VaultOperationLease.AcquireAsync(_vaultDir, cancellationToken, _customVault);
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
                ValidateVaultPayloadPath(entry.QuarantinePath);
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
                result.Success = true;
                result.RestoredPath = destPath;

                // 7. Veritabanı durumunu güncelle
                // Publication is already committed. Caller cancellation must not interrupt bookkeeping.
                await _database.UpdateStatusAsync(entry.Id, QuarantineStatus.Restored, DateTime.UtcNow, CancellationToken.None);

                result.Message = $"Dosya başarıyla geri yüklendi: '{destPath}'";
                return result;
            }
            catch (Exception ex)
            {
                result.AuditPending = result.Success;
                result.Message = result.Success
                    ? "Recovery was published, but metadata bookkeeping requires reconciliation."
                    : $"Geri yükleme başarısız: {ex.Message}";
                _logger?.LogError(ex, "Recovery failed or requires metadata reconciliation for item {Id}; published={Published}",
                    quarantineId, result.Success);
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

        /// <summary>Deletes a verified vault-local payload under a cross-process lease; IPC callers require the owner-authorized API.</summary>
        public async Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default)
        {
            using var operation = await VaultOperationLease.AcquireAsync(_vaultDir, cancellationToken, _customVault);
            var gate = _database.GetPathLock(Path.GetFullPath(_vaultDir) + "|entry|" + id);
            await gate.WaitAsync(cancellationToken);
            try { return await DeleteQuarantinedCoreAsync(id, cancellationToken); }
            finally { gate.Release(); }
        }

        private async Task<bool> DeleteQuarantinedCoreAsync(int id, CancellationToken cancellationToken)
        {
            var entry = await _database.GetEntryByIdAsync(id, cancellationToken);
            if (entry == null) return false;
            bool payloadRemoved = false;
            try
            {
                ValidateVaultPayloadPath(entry.QuarantinePath);
                // Cancellation is honored before destruction. In-place overwriting could destroy the
                // only recovery copy partially and then cancel; unlink the encrypted payload instead.
                // This is logical deletion, not a physical secure-erase promise (especially on SSDs).
                cancellationToken.ThrowIfCancellationRequested();
                File.Delete(entry.QuarantinePath);
                payloadRemoved = true;
                await _database.UpdateStatusAsync(id, QuarantineStatus.Deleted, cancellationToken: CancellationToken.None);
                return true;
            }
            catch (OperationCanceledException) when (!payloadRemoved) { throw; }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Quarantine payload deletion failed or requires metadata reconciliation; removed={Removed}, path={Path}",
                    payloadRemoved, entry.QuarantinePath);
                // A bookkeeping error cannot report that an irreversibly removed payload still exists.
                return payloadRemoved;
            }
        }
}
