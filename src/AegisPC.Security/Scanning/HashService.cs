using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;

namespace AegisPC.Security.Scanning
{
    public class HashService : IHashService
    {
        // 256 KB buffer — büyük dosyalarda syscall sayısını azaltır, NVMe SSD'lerde throughput artırır
        private const int BufferSize = 262144;

        public async Task<string> ComputeSha256Async(string filePath, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!File.Exists(filePath)) return string.Empty;

            using var hashMeasurement = ScanStageMeasurements.Measure(ScanStageTiming.Hash);
            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, BufferSize,
                    FileOptions.SequentialScan | FileOptions.Asynchronous);
                var hashBytes = await SHA256.HashDataAsync(stream, cancellationToken);
                return Convert.ToHexString(hashBytes).ToLowerInvariant();
            }
            catch (IOException ex) when (AegisPC.Core.Exceptions.OperatingSystemFileBlockException.TryGetKind(ex, out _))
            {
                AegisPC.Core.Exceptions.OperatingSystemFileBlockException.TryGetKind(ex, out var kind);
                throw new AegisPC.Core.Exceptions.OperatingSystemFileBlockException(kind, ex);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceWarning("SHA-256 unavailable ({0}); no content identity was produced.", ex.GetType().Name);
                return string.Empty;
            }
        }

        public async Task<string> ComputeSha1Async(string filePath, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!File.Exists(filePath)) return string.Empty;

            using var hashMeasurement = ScanStageMeasurements.Measure(ScanStageTiming.Hash);
            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, BufferSize,
                    FileOptions.SequentialScan | FileOptions.Asynchronous);
                var hashBytes = await SHA1.HashDataAsync(stream, cancellationToken);
                return Convert.ToHexString(hashBytes).ToLowerInvariant();
            }
            catch (OperationCanceledException) { throw; }
            catch
            {
                return string.Empty;
            }
        }
    }
}
