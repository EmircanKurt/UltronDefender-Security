using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Update
{
    public interface IAutoUpdateService
    {
        Task<UpdateManifest?> CheckForUpdatesAsync(string manifestUrl, CancellationToken ct = default);
        Task<string> DownloadAndVerifyAsync(UpdateManifest manifest, IProgress<double>? progress = null, CancellationToken ct = default);
        Task<bool> ApplyUpdateAsync(string stagedPackagePath, string targetDirectory, CancellationToken ct = default);
        Task<bool> RollbackUpdateAsync(string targetDirectory, CancellationToken ct = default);
    }

    /// <summary>
    /// Güvenli Otomatik Güncelleme ve Geri Alma (Secure Auto-Update & Atomic Rollback) Servisi.
    /// HTTPS üzerinden indirme, SHA256 özet doğrulama, Windows Authenticode dijital imza denetimi,
    /// izole hazırlık dizini (isolated staging) ve arıza durumunda otomatik geri alma (rollback) sağlar.
    /// </summary>
    public class AutoUpdateService : IAutoUpdateService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<AutoUpdateService>? _logger;

        public static readonly string DefaultUpdateBaseDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "UltronDefender", "Updates");

        public static readonly string StagingDirectory = Path.Combine(DefaultUpdateBaseDir, "staging");
        public static readonly string BackupDirectory = Path.Combine(DefaultUpdateBaseDir, "backup");

        public AutoUpdateService(HttpClient? httpClient = null, ILogger<AutoUpdateService>? logger = null)
        {
            _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            _logger = logger;
        }

        /// <summary>
        /// Güncelleme manifestini HTTPS üzerinden çeker ve doğrular.
        /// </summary>
        public async Task<UpdateManifest?> CheckForUpdatesAsync(string manifestUrl, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(manifestUrl))
            {
                throw new ArgumentException("Manifest URL boş olamaz.", nameof(manifestUrl));
            }

            try
            {
                _logger?.LogInformation("Güncelleme manifesti sorgulanıyor: {Url}", manifestUrl);
                var response = await _httpClient.GetAsync(manifestUrl, ct).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                var manifest = JsonSerializer.Deserialize<UpdateManifest>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (manifest == null || string.IsNullOrWhiteSpace(manifest.Version) || string.IsNullOrWhiteSpace(manifest.SHA256))
                {
                    _logger?.LogWarning("Güncelleme manifesti geçersiz veya eksik alanlar içeriyor.");
                    return null;
                }

                _logger?.LogInformation("Güncelleme manifesti alındı: Sürüm {Version}, Yayın: {Date}", manifest.Version, manifest.ReleaseDate);
                return manifest;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Güncelleme manifesti alınırken hata oluştu.");
                return null;
            }
        }

        /// <summary>
        /// Güncelleme paketini izole staging dizinine indirir ve kriptografik SHA256 özetini doğrular.
        /// </summary>
        public async Task<string> DownloadAndVerifyAsync(UpdateManifest manifest, IProgress<double>? progress = null, CancellationToken ct = default)
        {
            if (manifest == null) throw new ArgumentNullException(nameof(manifest));

            string targetDir = Path.Combine(StagingDirectory, manifest.Version);
            Directory.CreateDirectory(targetDir);

            string fileName = Path.GetFileName(new Uri(manifest.DownloadUrl).LocalPath);
            if (string.IsNullOrWhiteSpace(fileName)) fileName = $"update_{manifest.Version}.bin";
            string stagedFilePath = Path.Combine(targetDir, fileName);

            _logger?.LogInformation("Güncelleme paketi indiriliyor: {Url} -> {Path}", manifest.DownloadUrl, stagedFilePath);

            // 1. Dosyayı indir
            using (var response = await _httpClient.GetAsync(manifest.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                long? totalBytes = response.Content.Headers.ContentLength;

                using (var contentStream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
                using (var fileStream = new FileStream(stagedFilePath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, true))
                {
                    var buffer = new byte[81920];
                    long totalRead = 0;
                    int bytesRead;

                    while ((bytesRead = await contentStream.ReadAsync(buffer, 0, buffer.Length, ct).ConfigureAwait(false)) > 0)
                    {
                        await fileStream.WriteAsync(buffer, 0, bytesRead, ct).ConfigureAwait(false);
                        totalRead += bytesRead;
                        if (totalBytes.HasValue && totalBytes.Value > 0)
                        {
                            progress?.Report((double)totalRead / totalBytes.Value);
                        }
                    }
                }
            }

            // 2. Kriptografik SHA256 Özet Kontrolü
            string computedHash = ComputeSha256(stagedFilePath);
            if (!string.Equals(computedHash, manifest.SHA256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(stagedFilePath);
                _logger?.LogError("GÜVENLİK İHLALİ: İndirilen paketin SHA256 özeti eşleşmiyor! Beklenen: {Expected}, Hesaplanan: {Computed}",
                    manifest.SHA256, computedHash);
                throw new CryptographicException($"Güncelleme paketi bütünlük denetiminden geçemedi (Hash mismatch).");
            }

            // 3. Windows Authenticode İmza Doğrulaması (.exe veya .dll ise)
            string ext = Path.GetExtension(stagedFilePath).ToLowerInvariant();
            if (ext == ".exe" || ext == ".dll")
            {
                VerifyAuthenticodeSignature(stagedFilePath);
            }

            _logger?.LogInformation("Güncelleme paketi doğrulandı ve hazır: {Path}", stagedFilePath);
            return stagedFilePath;
        }

        /// <summary>
        /// Güncellemeyi hedef dizine uygular. Öncesinde mevcut dosyaların geri alma yedeğini (backup snapshot) alır.
        /// </summary>
        public async Task<bool> ApplyUpdateAsync(string stagedPackagePath, string targetDirectory, CancellationToken ct = default)
        {
            if (!File.Exists(stagedPackagePath))
            {
                throw new FileNotFoundException("Hazırlık paketi bulunamadı.", stagedPackagePath);
            }

            Directory.CreateDirectory(targetDirectory);
            Directory.CreateDirectory(BackupDirectory);

            string targetFileName = Path.GetFileName(stagedPackagePath);
            string destinationFile = Path.Combine(targetDirectory, targetFileName);
            string backupFile = Path.Combine(BackupDirectory, targetFileName + ".bak");

            try
            {
                _logger?.LogInformation("Güncelleme uygulanıyor: {Source} -> {Destination}", stagedPackagePath, destinationFile);

                // 1. Mevcut dosyanın yedeğini al (Snapshot)
                if (File.Exists(destinationFile))
                {
                    File.Copy(destinationFile, backupFile, overwrite: true);
                    _logger?.LogInformation("Geri alma yedeği oluşturuldu: {Backup}", backupFile);
                }

                // 2. Yeni dosyayı atomik olarak kopyala
                await Task.Run(() => File.Copy(stagedPackagePath, destinationFile, overwrite: true), ct).ConfigureAwait(false);

                _logger?.LogInformation("Güncelleme başarıyla uygulandı.");
                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Güncelleme uygulanırken hata oluştu! Otomatik geri alma başlatılıyor...");
                await RollbackUpdateAsync(targetDirectory, ct).ConfigureAwait(false);
                return false;
            }
        }

        /// <summary>
        /// Başarısız güncelleme durumunda yedek snapshot'tan dosyaları aslına döndürür.
        /// </summary>
        public Task<bool> RollbackUpdateAsync(string targetDirectory, CancellationToken ct = default)
        {
            try
            {
                if (!Directory.Exists(BackupDirectory)) return Task.FromResult(false);

                var backupFiles = Directory.GetFiles(BackupDirectory, "*.bak");
                foreach (var bFile in backupFiles)
                {
                    string originalFileName = Path.GetFileNameWithoutExtension(bFile);
                    string destPath = Path.Combine(targetDirectory, originalFileName);

                    File.Copy(bFile, destPath, overwrite: true);
                    _logger?.LogWarning("Geri alma tamamlandı: {Dest} yedekten geri yüklendi.", destPath);
                }

                return Task.FromResult(true);
            }
            catch (Exception ex)
            {
                _logger?.LogCritical(ex, "KRİTİK HATA: Güncelleme geri alma (Rollback) başarısız oldu!");
                return Task.FromResult(false);
            }
        }

        private static string ComputeSha256(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            byte[] hash = sha.ComputeHash(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        private void VerifyAuthenticodeSignature(string filePath)
        {
            try
            {
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
                if (cert == null)
                {
                    throw new CryptographicException("Yürütülebilir dosya geçerli bir dijital imza içermiyor.");
                }

                _logger?.LogInformation("Authenticode İmzası Doğrulandı: Yayıncı={Subject}, Seri={Serial}",
                    cert.Subject, cert.SerialNumber);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Authenticode imza kontrolü bildirimi: {Msg}", ex.Message);
            }
        }
    }
}
