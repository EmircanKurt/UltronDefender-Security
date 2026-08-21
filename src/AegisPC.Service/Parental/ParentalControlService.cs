using System;
using System.Security.Cryptography;
using System.Text;

namespace AegisPC.Service.Parental
{
    public class ParentalControlService
    {
        public static string HashPin(string pin, string salt)
        {
            if (string.IsNullOrEmpty(pin)) throw new ArgumentException("PIN cannot be null or empty", nameof(pin));
            if (string.IsNullOrEmpty(salt)) salt = "AegisParentalDefaultSalt";

            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(pin + salt);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToHexString(hash);
        }

        public static bool VerifyPin(string inputPin, string salt, string expectedHash)
        {
            if (string.IsNullOrEmpty(inputPin) || string.IsNullOrEmpty(expectedHash)) return false;
            var actualHash = HashPin(inputPin, salt);
            return string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsTimeLimitExceeded(int dailyLimitMinutes, int usedMinutes)
        {
            if (dailyLimitMinutes <= 0) return false; // 0 = unlimited
            return usedMinutes >= dailyLimitMinutes;
        }

        public static TimeSpan CalculateRemainingTime(int dailyLimitMinutes, int usedMinutes)
        {
            if (dailyLimitMinutes <= 0) return TimeSpan.MaxValue;
            int remaining = Math.Max(0, dailyLimitMinutes - usedMinutes);
            return TimeSpan.FromMinutes(remaining);
        }

        public static string MapWebCategory(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return "Unknown";

            var lower = url.ToLowerInvariant();
            if (lower.Contains("casino") || lower.Contains("bet") || lower.Contains("poker") || lower.Contains("gambling"))
            {
                return "Gambling";
            }
            if (lower.Contains("adult") || lower.Contains("porn") || lower.Contains("xxx") || lower.Contains("nsfw"))
            {
                return "Adult";
            }
            if (lower.Contains("steam") || lower.Contains("roblox") || lower.Contains("epicgames") || lower.Contains("twitch"))
            {
                return "Gaming";
            }
            if (lower.Contains("facebook") || lower.Contains("tiktok") || lower.Contains("instagram") || lower.Contains("twitter"))
            {
                return "SocialMedia";
            }

            return "General";
        }
    }
}
