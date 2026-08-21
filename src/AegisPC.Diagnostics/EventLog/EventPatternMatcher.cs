using System;
using System.Text.RegularExpressions;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Diagnostics.EventLog
{
    public static class EventPatternMatcher
    {
        public static CrashEvent? MatchCrashEvent(WindowsEventEntry entry)
        {
            if (entry == null) return null;

            bool isCrashEvent = entry.EventId is 1000 or 1002 or 1001 or 41;
            if (!isCrashEvent) return null;

            var (eventType, appName, exceptionCode, confidence) = MatchCrashPattern(
                entry.ProviderName,
                entry.EventId,
                entry.Message,
                entry.RawXml);

            return new CrashEvent
            {
                EventType = eventType,
                ApplicationName = appName,
                ExceptionCode = exceptionCode,
                EventId = entry.EventId,
                ProviderName = entry.ProviderName,
                OccurredAt = entry.TimeCreated,
                ConfidenceLevel = confidence
            };
        }

        public static (CrashEventType eventType, string appName, string? exceptionCode, ConfidenceLevel confidence) MatchCrashPattern(
            string provider,
            int eventId,
            string message,
            string? rawXml)
        {
            // 1. Application Error (ID 1000)
            if (eventId == 1000 && provider.Contains("Application Error", StringComparison.OrdinalIgnoreCase))
            {
                var appName = ExtractFaultingApplication(message, rawXml);
                var exceptionCode = ExtractExceptionCode(message, rawXml);
                return (CrashEventType.AppCrash, appName, exceptionCode, ConfidenceLevel.High);
            }

            // 2. Application Hang (ID 1002)
            if (eventId == 1002 && (provider.Contains("Application Hang", StringComparison.OrdinalIgnoreCase) || provider.Contains("Application Error", StringComparison.OrdinalIgnoreCase)))
            {
                var appName = ExtractFaultingApplication(message, rawXml);
                return (CrashEventType.AppHang, appName, null, ConfidenceLevel.High);
            }

            // 3. Windows Error Reporting (ID 1001)
            if (eventId == 1001 && provider.Contains("Windows Error Reporting", StringComparison.OrdinalIgnoreCase))
            {
                var appName = ExtractFaultingApplication(message, rawXml);
                return (CrashEventType.AppCrash, appName, null, ConfidenceLevel.Medium);
            }

            // 4. Kernel-Power (ID 41) - Unexpected Shutdown / BSOD
            if (eventId == 41 && provider.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase))
            {
                return (CrashEventType.UnexpectedShutdown, "Windows Kernel", "0x00000041", ConfidenceLevel.High);
            }

            // 5. BugCheck (ID 1001 in System log)
            if (eventId == 1001 && provider.Contains("BugCheck", StringComparison.OrdinalIgnoreCase))
            {
                return (CrashEventType.BSOD, "Windows System", ExtractExceptionCode(message, rawXml), ConfidenceLevel.High);
            }

            return (CrashEventType.AppCrash, "Bilinmeyen Uygulama", null, ConfidenceLevel.Low);
        }

        private static string ExtractFaultingApplication(string message, string? rawXml)
        {
            if (!string.IsNullOrEmpty(rawXml))
            {
                var match = Regex.Match(rawXml, @"<Data Name=""(?:AppName|FaultingApplicationName)"">([^<]+)</Data>", RegexOptions.IgnoreCase);
                if (match.Success) return match.Groups[1].Value;
            }

            if (!string.IsNullOrEmpty(message))
            {
                var match = Regex.Match(message, @"(?:Hatalı uygulama adı|Faulting application name):\s*([^\r\n,]+)", RegexOptions.IgnoreCase);
                if (match.Success) return match.Groups[1].Value.Trim();
            }

            return "Uygulama";
        }

        private static string? ExtractExceptionCode(string message, string? rawXml)
        {
            if (!string.IsNullOrEmpty(rawXml))
            {
                var match = Regex.Match(rawXml, @"<Data Name=""(?:ExceptionCode|FaultingExceptionCode)"">([^<]+)</Data>", RegexOptions.IgnoreCase);
                if (match.Success) return match.Groups[1].Value;
            }

            if (!string.IsNullOrEmpty(message))
            {
                var match = Regex.Match(message, @"(?:Özel durum kodu|Exception code):\s*(0x[0-9a-fA-F]+)", RegexOptions.IgnoreCase);
                if (match.Success) return match.Groups[1].Value.Trim();
            }

            return null;
        }
    }
}
