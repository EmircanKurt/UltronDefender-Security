using System;
using System.IO;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class EntropyCalculatorTests
    {
        [Fact]
        public void CalculateEntropy_UniformData_ShouldHaveLowEntropy()
        {
            var zeros = new byte[1024];
            double entropy = EntropyCalculator.CalculateEntropy(zeros);
            Assert.Equal(0.0, entropy);
        }

        [Fact]
        public void CalculateEntropy_RandomBytes_ShouldHaveHighEntropy()
        {
            var randomBytes = new byte[4096];
            new Random(42).NextBytes(randomBytes);

            double entropy = EntropyCalculator.CalculateEntropy(randomBytes);
            Assert.InRange(entropy, 7.5, 8.0);
        }

        [Fact]
        public void IsSuspiciouslyHighEntropy_AboveThreshold_ReturnsTrue()
        {
            Assert.True(EntropyCalculator.IsSuspiciouslyHighEntropy(7.3));
            Assert.False(EntropyCalculator.IsSuspiciouslyHighEntropy(5.2));
        }
    }
}
