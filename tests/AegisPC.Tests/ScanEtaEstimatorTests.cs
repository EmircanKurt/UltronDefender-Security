using System;
using System.Threading;
using AegisPC.Core.Enums;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class ScanEtaEstimatorTests
    {
        [Fact]
        public void ScanEtaEstimator_WarmupPhase_ReturnsLowConfidence()
        {
            var estimator = new ScanEtaEstimator();

            // First few immediate updates within warmup window (< 2.5s and < 6 samples)
            var (remainingSec, confidence, formatted) = estimator.Update(totalFiles: 1000, scannedFiles: 2);

            Assert.Equal(ConfidenceLevel.Low, confidence);
            Assert.Contains("Hesaplanıyor", formatted);
        }

        [Fact]
        public void ScanEtaEstimator_CompletedScan_ReturnsZeroRemainingAndHighConfidence()
        {
            var estimator = new ScanEtaEstimator();

            var (remainingSec, confidence, formatted) = estimator.Update(totalFiles: 100, scannedFiles: 100);

            Assert.Equal(0, remainingSec);
            Assert.Equal(ConfidenceLevel.High, confidence);
            Assert.Equal("Tamamlandı", formatted);
        }

        [Fact]
        public void ScanEtaEstimator_Reset_ClearsEstimatorState()
        {
            var estimator = new ScanEtaEstimator();

            estimator.Update(totalFiles: 50, scannedFiles: 50);
            estimator.Reset();

            var (remainingSec, confidence, formatted) = estimator.Update(totalFiles: 100, scannedFiles: 1);
            Assert.Equal(ConfidenceLevel.Low, confidence);
            Assert.Null(remainingSec);
            Assert.Contains("Hesaplanıyor", formatted);
        }

        [Fact]
        public void ScanEtaEstimator_Formatting_HandlesVariousIntervals()
        {
            var estimator = new ScanEtaEstimator();

            // Zero total files edge case
            var resultZero = estimator.Update(totalFiles: 0, scannedFiles: 0);
            Assert.Equal(ConfidenceLevel.Low, resultZero.Confidence);
            Assert.Contains("Hesaplanıyor", resultZero.FormattedText);
        }
    }
}
