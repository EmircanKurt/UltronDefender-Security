using System;
using AegisPC.Core.Helpers;
using Xunit;

namespace AegisPC.Tests
{
    public class ParentalControlTests
    {
        [Fact]
        public void Test_PinHash()
        {
            var pin = "1234";
            var salt = "TestSalt99";
            var hash = ParentalControlService.HashPin(pin, salt);

            Assert.False(string.IsNullOrEmpty(hash));
            Assert.True(ParentalControlService.VerifyPin("1234", salt, hash));
            Assert.False(ParentalControlService.VerifyPin("9999", salt, hash));
        }

        [Fact]
        public void Test_TimeLimitCalculation()
        {
            // Limit 120 mins, used 130 mins -> Exceeded
            Assert.True(ParentalControlService.IsTimeLimitExceeded(120, 130));
            // Limit 120 mins, used 60 mins -> Not exceeded
            Assert.False(ParentalControlService.IsTimeLimitExceeded(120, 60));

            var remaining = ParentalControlService.CalculateRemainingTime(120, 90);
            Assert.Equal(TimeSpan.FromMinutes(30), remaining);
        }

        [Fact]
        public void Test_CategoryMapping()
        {
            Assert.Equal("Gambling", ParentalControlService.MapWebCategory("https://best-casino-bet.com"));
            Assert.Equal("Gaming", ParentalControlService.MapWebCategory("https://store.steampowered.com"));
            Assert.Equal("SocialMedia", ParentalControlService.MapWebCategory("https://instagram.com/p/123"));
            Assert.Equal("General", ParentalControlService.MapWebCategory("https://docs.microsoft.com"));
        }
    }
}
