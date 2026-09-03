using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Gerçek zamanlı koruma için dosya yazma kilidi ve indirme kararlılığı kontrolcüsü arayüzü.
    /// </summary>
    public interface IRealTimeStabilityChecker
    {
        /// <summary>
        /// Dosya yazımı devam ederken (örneğin web tarayıcısı indirme yaparken) dosyanın tamamlanmasını adaptif bekler.
        /// </summary>
        Task<bool> WaitForFileStabilityAsync(string filePath, CancellationToken ct);
    }

    /// <summary>
    /// Dosya yazımı devam ederken (örneğin web tarayıcısı .exe indirirken) dosyanın tamamlanmasını adaptif bekleyen kontrolcü.
    /// Büyük dosyalarda (GB) dosya boyutu değiştikçe bekler, boyut sabitlendiğinde analize izin verir.
    /// </summary>
    public class RealTimeStabilityChecker : IRealTimeStabilityChecker
    {
        /// <summary>
        /// Dosya yazımı devam ederken dosyanın tamamlanmasını ve kilitlerin serbest kalmasını bekler.
        /// </summary>
        public async Task<bool> WaitForFileStabilityAsync(string filePath, CancellationToken ct)
        {
            if (!File.Exists(filePath)) return false;

            long lastSize = -1;
            int stableReadCount = 0;
            const int maxTotalWaitMs = 6000;
            var sw = Stopwatch.StartNew();

            while (sw.ElapsedMilliseconds < maxTotalWaitMs && !ct.IsCancellationRequested)
            {
                if (!File.Exists(filePath)) return false;

                try
                {
                    var fi = new FileInfo(filePath);
                    long currentSize = fi.Length;

                    // Dosyaya paylaşımlı okuma erişimi dene
                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        if (currentSize > 0 && currentSize == lastSize)
                        {
                            stableReadCount++;
                            if (stableReadCount >= 2) // Art arda 2 kontrolde dosya boyutu değişmediyse yazım tamamdır
                            {
                                return true;
                            }
                        }
                        else
                        {
                            stableReadCount = 0;
                            lastSize = currentSize;
                        }
                    }
                }
                catch (IOException)
                {
                    stableReadCount = 0; // Dosya hâlâ başka bir işlem tarafından kilitli / yazılıyor
                }

                await Task.Delay(40, ct);
            }

            return File.Exists(filePath);
        }
    }
}
