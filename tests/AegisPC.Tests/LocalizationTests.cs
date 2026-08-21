using System;
using AegisPC.Core.Localization;
using Xunit;

namespace AegisPC.Tests
{
    public class LocalizationTests
    {
        [Fact]
        public void Test_Localization_SwitchLanguage_ReturnsCorrectStrings()
        {
            var loc = new LocalizationService();

            loc.SetLanguage("en-US");
            Assert.Equal("en-US", loc.CurrentLanguage);
            Assert.Equal("Quick Scan", loc.GetString("Scan_Quick"));
            Assert.Equal("System Protected", loc["Dashboard_Protected"]);

            loc.SetLanguage("tr-TR");
            Assert.Equal("tr-TR", loc.CurrentLanguage);
            Assert.Equal("Hizli Tarama", loc.GetString("Scan_Quick"));
            Assert.Equal("Sisteminiz Guvende", loc["Dashboard_Protected"]);
        }

        [Fact]
        public void Test_Localization_Fallback_ReturnsKeyWhenMissing()
        {
            var loc = new LocalizationService();
            loc.SetLanguage("en-US");

            var missing = loc.GetString("NonExistentKey_12345", "FallbackDefault");
            Assert.Equal("FallbackDefault", missing);
        }
    }
}
