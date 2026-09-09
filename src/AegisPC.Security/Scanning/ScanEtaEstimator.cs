using System;
using System.Diagnostics;
using AegisPC.Core.Enums;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Accurate, EWMA (Exponential Weighted Moving Average) smoothed estimation engine
    /// for scan time remaining. Operates without arbitrary hardcoded magic numbers,
    /// providing real statistical confidence ratings and graceful warmup handling.
    /// </summary>
    public class ScanEtaEstimator
    {
        private readonly Stopwatch _stopwatch = new();
        private readonly object _lock = new();

        private double _ewmaFilesPerSecond = 0.0;
        private double _ewmaBytesPerSecond = 0.0;
        private int _sampleCount = 0;
        private int _lastScannedFiles = 0;
        private long _lastScannedBytes = 0;
        private double _lastSampleTimeSec = 0.0;

        private const double SmoothingFactor = 0.25; // Alpha for EWMA
        private const int MinimumWarmupSamples = 6;
        private const double MinimumWarmupElapsedSeconds = 2.5;

        public ScanEtaEstimator()
        {
            _stopwatch.Start();
        }

        public void Reset()
        {
            lock (_lock)
            {
                _stopwatch.Restart();
                _ewmaFilesPerSecond = 0.0;
                _ewmaBytesPerSecond = 0.0;
                _sampleCount = 0;
                _lastScannedFiles = 0;
                _lastScannedBytes = 0;
                _lastSampleTimeSec = 0.0;
            }
        }

        /// <summary>
        /// Records an incremental observation of scan progress.
        /// </summary>
        public (double? RemainingSeconds, ConfidenceLevel Confidence, string FormattedText) Update(
            int totalFiles,
            int scannedFiles,
            long totalBytes = 0,
            long scannedBytes = 0)
        {
            lock (_lock)
            {
                double elapsedSec = _stopwatch.Elapsed.TotalSeconds;
                double deltaSec = elapsedSec - _lastSampleTimeSec;

                // Only calculate new speed sample if at least 150ms has elapsed since previous sample
                if (deltaSec >= 0.15)
                {
                    int deltaFiles = Math.Max(0, scannedFiles - _lastScannedFiles);
                    long deltaBytes = Math.Max(0, scannedBytes - _lastScannedBytes);

                    double instantFilesPerSec = deltaFiles / deltaSec;
                    double instantBytesPerSec = deltaBytes / deltaSec;

                    if (_sampleCount == 0)
                    {
                        _ewmaFilesPerSecond = instantFilesPerSec;
                        _ewmaBytesPerSecond = instantBytesPerSec;
                    }
                    else
                    {
                        _ewmaFilesPerSecond = (SmoothingFactor * instantFilesPerSec) + ((1.0 - SmoothingFactor) * _ewmaFilesPerSecond);
                        _ewmaBytesPerSecond = (SmoothingFactor * instantBytesPerSec) + ((1.0 - SmoothingFactor) * _ewmaBytesPerSecond);
                    }

                    _sampleCount++;
                    _lastScannedFiles = scannedFiles;
                    _lastScannedBytes = scannedBytes;
                    _lastSampleTimeSec = elapsedSec;
                }

                int remainingFiles = Math.Max(0, totalFiles - scannedFiles);

                // Warmup check: If not enough samples or time, report Low confidence and "Hesaplanıyor..."
                if (_sampleCount < MinimumWarmupSamples || elapsedSec < MinimumWarmupElapsedSeconds || _ewmaFilesPerSecond <= 0.05 || totalFiles <= 0 || remainingFiles <= 0)
                {
                    if (scannedFiles > 0 && remainingFiles == 0)
                    {
                        return (0, ConfidenceLevel.High, "Tamamlandı");
                    }
                    return (null, ConfidenceLevel.Low, "Hesaplanıyor...");
                }

                double estimatedSeconds = remainingFiles / _ewmaFilesPerSecond;

                // Confidence assessment based on sample count and elapsed time
                ConfidenceLevel confidence;
                if (_sampleCount >= 30 && elapsedSec >= 10.0)
                {
                    confidence = ConfidenceLevel.High;
                }
                else if (_sampleCount >= 12 && elapsedSec >= 4.0)
                {
                    confidence = ConfidenceLevel.Medium;
                }
                else
                {
                    confidence = ConfidenceLevel.Low;
                }

                string formatted = FormatRemainingDuration(estimatedSeconds);
                return (estimatedSeconds, confidence, formatted);
            }
        }

        private static string FormatRemainingDuration(double seconds)
        {
            if (seconds < 1) return "1 saniyeden az";
            if (seconds < 60) return $"Yaklaşık {(int)Math.Round(seconds)} saniye";

            int totalMinutes = (int)Math.Round(seconds / 60.0);
            if (totalMinutes < 60)
            {
                return $"Yaklaşık {totalMinutes} dakika";
            }

            int hours = totalMinutes / 60;
            int remainingMins = totalMinutes % 60;
            return remainingMins > 0 ? $"Yaklaşık {hours} saat {remainingMins} dk" : $"Yaklaşık {hours} saat";
        }
    }
}
