using System;
using AegisPC.Security.Safety;
using Xunit;

namespace AegisPC.Tests
{
    public class FalsePositiveRegressionTests
    {
        [Fact]
        public void TrustedCommercialApp_InLegitimateLocation_ReceivesBoundedReputationWithoutBypass()
        {
            string appPath = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
            var result = TrustedSoftwarePolicy.EvaluateTrust(
                appPath,
                publisher: "Google LLC",
                isSigned: true,
                isSignatureValid: true,
                isKnownLocation: false);

            Assert.False(result.IsFullyTrusted, "A signature and location cannot establish a clean verdict.");
            Assert.True(result.IsCommercialTrusted);
            Assert.Equal(-10, result.TrustScoreDiscount);
        }

        [Fact]
        public void LegitimateInstaller_InDownloadsFolder_GetsTrustedDiscount()
        {
            string downloadPath = @"C:\Users\User\Downloads\SteamSetup.exe";
            var result = TrustedSoftwarePolicy.EvaluateTrust(
                downloadPath,
                publisher: "Valve Corporation",
                isSigned: true,
                isSignatureValid: true,
                isKnownLocation: false);

            Assert.True(result.IsCommercialTrusted);
            Assert.False(result.IsFullyTrusted, "Not in install location yet, so not fully trusted.");
            Assert.Equal(-10, result.TrustScoreDiscount);
        }

        [Fact]
        public void CorruptedOrTamperedSignature_IncreasesRisk()
        {
            string suspiciousPath = @"C:\Users\User\Downloads\trojan.exe";
            var result = TrustedSoftwarePolicy.EvaluateTrust(
                suspiciousPath,
                publisher: "Unknown or Broken",
                isSigned: true,
                isSignatureValid: false,
                isKnownLocation: false);

            Assert.False(result.IsFullyTrusted);
            Assert.True(result.TrustScoreDiscount > 0, "Invalid/tampered signature MUST contribute to risk score!");
            Assert.Contains("Geçersiz veya tahrif edilmiş", result.Reason);
        }

        [Fact]
        public void DeveloperTooling_Publishers_AreRecognizedAsTrusted()
        {
            Assert.False(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("CN=Python Software Foundation, O=Python"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Python Software Foundation"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Node.js Foundation"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Rust Foundation"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Docker Inc"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Git for Windows"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Atlassian Pty Ltd"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Wireshark Foundation"));
        }

        [Fact]
        public void UserWritableProgramsFolderDoesNotEstablishTrust()
        {
            // Modern per-user installers (VS Code, Python, Discord) install to AppData\Local\Programs
            string vscodePath = @"C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe";
            Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(vscodePath));

            string discordPath = @"C:\Users\User\AppData\Local\Programs\Discord\Discord.exe";
            Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(discordPath));

            string pythonPath = @"C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe";
            Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(pythonPath));
        }
    }
}
