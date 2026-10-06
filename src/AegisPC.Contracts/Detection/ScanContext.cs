using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Detection
{
    /// <summary>
    /// Tek geçişli özet (single-pass hash) önbelleği ve analiz katmanları arasında paylaşılan birleşik tarama bağlamı.
    /// Tekrarlayan disk I/O ve hash hesaplamalarını önler.
    /// </summary>
    public class ScanContext
    {
        private string? _sha256;
        private byte[]? _headerBytes;
        private readonly SemaphoreSlim _hashGate = new(1, 1);
        private readonly SemaphoreSlim _signatureGate = new(1, 1);
        private SignatureInfo? _signature;

        public string FilePath { get; set; } = string.Empty;
        public string FileName => Path.GetFileName(FilePath);
        public long FileSize { get; set; }
        public DateTime? LastWriteTimeUtc { get; set; }
        /// <summary>Shares structural content identity computed from the caller's locked source, never filename trust.</summary>
        public FileContentClassification? ContentClassification { get; set; }
        /// <summary>Optional borrowed read-only source held by the caller until sequential detector evaluation completes; never disposed here.</summary>
        public Stream? LockedContent { get; set; }

        public string? SHA256
        {
            get => _sha256;
            set => _sha256 = value;
        }

        public byte[]? HeaderBytes
        {
            get => _headerBytes;
            set => _headerBytes = value;
        }

        public bool HasSha256 => !string.IsNullOrEmpty(_sha256);

        public ScanContext()
        {
        }

        public ScanContext(string filePath, string? precomputedSha256 = null, long fileSize = 0)
        {
            FilePath = filePath;
            _sha256 = precomputedSha256;
            FileSize = fileSize;
        }

        /// <summary>
        /// SHA-256 özetini tek bir kez hesaplar ve önbelleğe alır. Sonraki çağrılarda disk I/O yapılmaz.
        /// </summary>
        public async Task<string> GetOrComputeSha256Async(IHashService hashService, CancellationToken ct = default)
        {
            await _hashGate.WaitAsync(ct);
            try
            {
                if (!string.IsNullOrEmpty(_sha256)) return _sha256;
                _sha256 = await hashService.ComputeSha256Async(FilePath, ct);
                return _sha256;
            }
            finally { _hashGate.Release(); }
        }

        public async Task<SignatureInfo> GetOrVerifySignatureAsync(ISignatureVerifier verifier, CancellationToken ct = default)
        {
            await _signatureGate.WaitAsync(ct);
            try { return _signature ??= await verifier.VerifySignatureAsync(FilePath, ct); }
            finally { _signatureGate.Release(); }
        }

        /// <summary>
        /// İlk baytları (magic bytes) tek bir kez okur ve önbelleğe alır.
        /// </summary>
        public async Task<ReadOnlyMemory<byte>> GetOrReadHeaderBytesAsync(int maxBytes = 64, CancellationToken ct = default)
        {
            if (_headerBytes != null && _headerBytes.Length >= maxBytes)
            {
                return _headerBytes.AsMemory(0, maxBytes);
            }

            if (!File.Exists(FilePath))
            {
                return ReadOnlyMemory<byte>.Empty;
            }

            byte[] buffer = new byte[maxBytes];
            await using var fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, true);
            int read = await fs.ReadAsync(buffer, 0, maxBytes, ct);
            _headerBytes = buffer.AsSpan(0, read).ToArray();
            return _headerBytes;
        }

        public DetectionContext ToDetectionContext()
        {
            return new DetectionContext
            {
                FilePath = FilePath,
                FileSize = FileSize,
                SHA256 = _sha256,
                LastWriteTimeUtc = LastWriteTimeUtc,
                ContentClassification = ContentClassification,
                SharedScan = this
            };
        }
    }
}
