using System;
using AegisPC.Core.Exceptions;
using Xunit;

namespace AegisPC.Tests
{
    [Trait("Category", "Unit")]
    public class CustomExceptionTests
    {
        [Fact]
        public void AegisSecurityException_InheritanceAndConstructors()
        {
            var ex1 = new AegisSecurityException();
            Assert.NotNull(ex1);
            Assert.IsAssignableFrom<Exception>(ex1);

            var ex2 = new AegisSecurityException("Security warning");
            Assert.Equal("Security warning", ex2.Message);

            var inner = new InvalidOperationException("Inner error");
            var ex3 = new AegisSecurityException("Outer error", inner);
            Assert.Equal("Outer error", ex3.Message);
            Assert.Same(inner, ex3.InnerException);
        }

        [Fact]
        public void QuarantineException_PropertiesAndContext()
        {
            var inner = new UnauthorizedAccessException("Access denied");
            var ex = new QuarantineException("Kasa kilitleme hatası", "C:\\Malware\\trojan.exe", "QID-992", inner);

            Assert.IsAssignableFrom<AegisSecurityException>(ex);
            Assert.Equal("Kasa kilitleme hatası", ex.Message);
            Assert.Equal("C:\\Malware\\trojan.exe", ex.TargetFilePath);
            Assert.Equal("QID-992", ex.QuarantineId);
            Assert.Same(inner, ex.InnerException);
        }

        [Fact]
        public void DetectionEngineException_PropertiesAndContext()
        {
            var inner = new TimeoutException("Analysis timeout");
            var ex = new DetectionEngineException("Dedektör zaman aşımı", "ScriptHeuristicDetector", "script.ps1", inner);

            Assert.IsAssignableFrom<AegisSecurityException>(ex);
            Assert.Equal("Dedektör zaman aşımı", ex.Message);
            Assert.Equal("ScriptHeuristicDetector", ex.DetectorName);
            Assert.Equal("script.ps1", ex.InspectedPath);
            Assert.Same(inner, ex.InnerException);
        }

        [Fact]
        public void ScanEngineException_PropertiesAndContext()
        {
            var inner = new System.IO.IOException("Disk read failure");
            var ex = new ScanEngineException("Tarama dizini okunamadı", "D:\\Games", inner);

            Assert.IsAssignableFrom<AegisSecurityException>(ex);
            Assert.Equal("Tarama dizini okunamadı", ex.Message);
            Assert.Equal("D:\\Games", ex.TargetPath);
            Assert.Same(inner, ex.InnerException);
        }

        [Fact]
        public void ServiceIpcException_PropertiesAndContext()
        {
            var inner = new System.IO.IOException("Pipe broken");
            var ex = new ServiceIpcException("IPC boru hattı koptu", "AegisPCPipe", inner);

            Assert.IsAssignableFrom<AegisSecurityException>(ex);
            Assert.Equal("IPC boru hattı koptu", ex.Message);
            Assert.Equal("AegisPCPipe", ex.PipeName);
            Assert.Same(inner, ex.InnerException);
        }

        [Fact]
        public void ConfigurationException_PropertiesAndContext()
        {
            var inner = new System.Security.Cryptography.CryptographicException("DPAPI decrypt failed");
            var ex = new ConfigurationException("Şifreli ayar yüklenemedi", "AutoQuarantineThreshold", inner);

            Assert.IsAssignableFrom<AegisSecurityException>(ex);
            Assert.Equal("Şifreli ayar yüklenemedi", ex.Message);
            Assert.Equal("AutoQuarantineThreshold", ex.ConfigurationKey);
            Assert.Same(inner, ex.InnerException);
        }
    }
}
