using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Security.Scanning
{
    public static class EntropyCalculator
    {
        public static double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0.0;

            var frequencies = new long[256];
            for (int i = 0; i < data.Length; i++)
            {
                frequencies[data[i]]++;
            }

            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] > 0)
                {
                    double p = (double)frequencies[i] / data.Length;
                    entropy -= p * Math.Log2(p);
                }
            }

            return Math.Round(entropy, 3);
        }

        public static bool IsSuspiciouslyHighEntropy(double entropy) => entropy >= 7.2;

        public static async Task<double> CalculateEntropyAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (!File.Exists(filePath)) return 0.0;

            const int maxBytesToRead = 512 * 1024; // 512 KB örnekleme — Shannon entropisi için %99.99 hassasiyet yeterlidir
            var frequencies = new long[256];
            long totalBytes = 0;

            byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 8192, useAsync: true);
                int bytesRead;
                while ((bytesRead = await stream.ReadAsync(buffer.AsMemory(0, 8192), cancellationToken)) > 0)
                {
                    for (int i = 0; i < bytesRead; i++)
                    {
                        frequencies[buffer[i]]++;
                    }
                    totalBytes += bytesRead;
                    if (totalBytes >= maxBytesToRead) break;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            if (totalBytes == 0) return 0.0;

            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] > 0)
                {
                    double p = (double)frequencies[i] / totalBytes;
                    entropy -= p * Math.Log2(p);
                }
            }

            return Math.Round(entropy, 3);
        }
    }
}
