using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Safety;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// AES-256 şifreli, SQLite ACID veritabanı indeksli, transactional rollback korumalı ve güvenli geri yükleme/silme özellikli Karantina Servisi.
    /// TransactionalQuarantineEngine ile birleştirilmiş tekil üretim motorudur.
    /// </summary>
    public class QuarantineService : IQuarantineService, IContentBoundQuarantineService, IDisposable
    {
        private readonly IHashService _hashService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger<QuarantineService>? _logger;
        private readonly TransactionalQuarantineEngine _engine;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IExclusionService? _exclusionService;
        private readonly IFileHashMatcher? _fileHashMatcher;

        public event Action<QuarantineEntry>? OnFileQuarantined;
        public event Action<int>? OnFileRestored;
        public event Action<int>? OnFileDeleted;

        public string? LastError { get; private set; }

        public QuarantineService(
            IHashService hashService,
            IAuditLogService? auditLogService = null,
            ILogger<QuarantineService>? logger = null,
            string? customVaultDir = null,
            AegisPC.Contracts.Safety.IProtectedPathGuard? protectedPathGuard = null,
            AegisPC.Contracts.Safety.IReparsePointGuard? reparsePointGuard = null,
            ISignatureVerifier? signatureVerifier = null,
            IExclusionService? exclusionService = null,
            IFileHashMatcher? fileHashMatcher = null)
        {
            _hashService = hashService;
            _auditLogService = auditLogService;
            _logger = logger;
            _signatureVerifier = signatureVerifier ?? new SignatureVerifier();
            _exclusionService = exclusionService;
            _fileHashMatcher = fileHashMatcher;

            _engine = new TransactionalQuarantineEngine(
                protectedPathGuard: protectedPathGuard,
                reparsePointGuard: reparsePointGuard,
                hashService: hashService,
                customVaultDir: customVaultDir);
        }

        public Task<bool> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken = default)
            => QuarantineCoreAsync(path, reason, null, cancellationToken);

        /// <summary>Contains only matching detected content, without terminating processes holding the file.</summary>
        public Task<bool> TryQuarantineFileAsync(string path, string reason, string expectedSha256, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(expectedSha256))
            {
                LastError = "Doğrulanmış içerik özeti olmadan otomatik karantina uygulanmadı.";
                return Task.FromResult(false);
            }
            return QuarantineCoreAsync(path, reason, expectedSha256, cancellationToken);
        }

        private async Task<bool> QuarantineCoreAsync(string path, string reason, string? expectedSha256, CancellationToken cancellationToken)
        {
            LastError = null;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return false;

            try
            {
                var canonicalPath = Path.GetFullPath(path);

                // Authenticode & Microsoft Core Binary Guard:
                // Sistem ve program dizinlerindeki geçerli Microsoft imzalı dosyalar asla otomatik karantinaya alınamaz.
                if (AegisPC.Core.Helpers.PathHelper.IsKnownSafePath(canonicalPath))
                {
                    var sig = await _signatureVerifier.VerifySignatureAsync(canonicalPath, cancellationToken);
                    if (sig.IsValid && TrustedSoftwarePolicy.IsTrustedOsPublisher(sig.Publisher))
                    {
                        _logger?.LogWarning("Refusing automatic quarantine of valid Microsoft-signed binary in system path: {Path} (Publisher: '{Publisher}'). Safety Guard Active.", canonicalPath, sig.Publisher);
                        return false;
                    }
                }

                // Hosts and System32 Tasks Guard: Never delete critical Windows hosts file or system tasks
                if (canonicalPath.Contains(@"\drivers\etc\hosts", StringComparison.OrdinalIgnoreCase) ||
                    canonicalPath.Contains(@"\System32\Tasks", StringComparison.OrdinalIgnoreCase))
                {
                    _logger?.LogWarning("Refusing quarantine of critical Windows network configuration or system tasks: {Path}", canonicalPath);
                    return false;
                }

                var request = new QuarantineRequest
                {
                    TargetFilePath = canonicalPath,
                    ThreatReason = reason,
                    ForceKillHoldingProcesses = false,
                    WipeOriginalPayloadBytes = true,
                    ExpectedSha256 = expectedSha256
                };

                var txResult = await _engine.ExecuteQuarantineAsync(request, cancellationToken);

                if (!txResult.Success)
                {
                    LastError = txResult.Message;
                    _logger?.LogWarning("Quarantine execution failed for {Path}: {Message}", canonicalPath, txResult.Message);
                    return false;
                }

                var entry = await _engine.GetItemByIdAsync(txResult.QuarantineId, cancellationToken);
                if (entry != null)
                {
                    try
                    {
                        OnFileQuarantined?.Invoke(entry);
                    }
                    catch (Exception eventEx)
                    {
                        _logger?.LogWarning(eventEx, "Quarantine notification subscriber failed for {Path}", canonicalPath);
                    }
                }

                if (_auditLogService != null)
                {
                    try
                    {
                        await _auditLogService.LogActionAsync(
                            AuditAction.FileQuarantined,
                            "File",
                            Path.GetFileName(canonicalPath),
                            canonicalPath,
                            reason,
                            AuditResult.Success,
                            cancellationToken: cancellationToken);
                    }
                    catch (Exception auditEx)
                    {
                        _logger?.LogWarning(auditEx, "Audit logging failed for quarantine of {Path}", canonicalPath);
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
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
            LastError = null;

            var entry = await _engine.GetItemByIdAsync(id, cancellationToken);
            if (entry == null || entry.Status != QuarantineStatus.Quarantined)
            {
                LastError = "Kasa kaydı bulunamadı veya dosya zaten geri yüklenmiş/silinmiş.";
                return false;
            }

            var destination = string.IsNullOrWhiteSpace(customDestinationPath) ? entry.OriginalPath : customDestinationPath;

            // Dosya kilitli mi kontrolü
            if (File.Exists(destination))
            {
                try
                {
                    using var testStream = new FileStream(destination, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                }
                catch (IOException)
                {
                    LastError = "Hedef dosya başka bir program tarafından kullanılıyor (dosya kullanımda / kilitli).";
                    _logger?.LogWarning("Quarantine restore failed: Target file is locked or in use: {Destination}", destination);
                    return false;
                }
                catch (UnauthorizedAccessException uex)
                {
                    LastError = "Yönetici yetkisi gerekli: Hedef dosyaya yazma yetkisi yok.";
                    _logger?.LogWarning(uex, "Quarantine restore failed: Unauthorized access to target file: {Destination}", destination);
                    return false;
                }
            }

            var restoreResult = await _engine.ExecuteRestoreAsync(id, customDestinationPath, cancellationToken);

            if (!restoreResult.Success)
            {
                LastError = restoreResult.Message;
                return false;
            }

            // Cache invalidation
            _exclusionService?.AddTemporaryContentExclusion(restoreResult.RestoredPath, entry.SHA256,
                TimeSpan.FromMinutes(5), "Geri yükleme: yalnız doğrulanmış dosya içeriğine geçici izin");
            _fileHashMatcher?.InvalidateCache(restoreResult.RestoredPath);

            try
            {
                OnFileRestored?.Invoke(id);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "OnFileRestored event handler failed for ID {Id}", id);
            }

            return true;
        }

        public async Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default)
        {
            LastError = null;
            bool deleted = await _engine.DeleteQuarantinedAsync(id, cancellationToken);
            if (deleted)
            {
                try
                {
                    OnFileDeleted?.Invoke(id);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "OnFileDeleted event handler failed for ID {Id}", id);
                }
            }
            return deleted;
        }

        public Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken cancellationToken = default)
        {
            return _engine.GetItemByIdAsync(id, cancellationToken);
        }

        public Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken cancellationToken = default)
        {
            return _engine.GetQuarantinedItemsAsync(cancellationToken);
        }

        public void Dispose()
        {
            _engine?.Dispose();
        }
    }
}
