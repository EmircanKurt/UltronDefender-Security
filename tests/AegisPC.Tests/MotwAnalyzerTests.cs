using System;
using AegisPC.Core.Helpers;
using Xunit;

namespace AegisPC.Tests
{
    public class MotwAnalyzerTests
    {
        [Fact]
        public void Test_ParseZoneIdentifier()
        {
            var content = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/download\r\nHostUrl=https://cdn.example.com/payload.exe";
            var result = MotwAnalyzer.ParseZoneIdentifierContent(content);

            Assert.True(result.HasMotw);
            Assert.Equal(3, result.ZoneId);
            Assert.Equal(SecurityZone.Internet, result.Zone);
            Assert.Equal("https://cdn.example.com/payload.exe", result.HostUrl);
            Assert.Equal("https://example.com/download", result.ReferrerUrl);
            Assert.True(result.IsFromInternet);
        }

        [Fact]
        public void Test_ZoneId3_IsInternet()
        {
            var content = "[ZoneTransfer]\nZoneId=3";
            var result = MotwAnalyzer.ParseZoneIdentifierContent(content);

            Assert.Equal(SecurityZone.Internet, result.Zone);
            Assert.True(result.IsFromInternet);
        }

        [Fact]
        public void Test_NoMotw_IsLocal()
        {
            var result = MotwAnalyzer.ParseZoneIdentifierContent(string.Empty);

            Assert.False(result.HasMotw);
            Assert.Equal(SecurityZone.LocalMachine, result.Zone);
            Assert.False(result.IsFromInternet);
        }
    }
}
