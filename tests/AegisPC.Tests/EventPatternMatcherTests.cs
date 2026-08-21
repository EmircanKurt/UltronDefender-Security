using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Diagnostics.EventLog;
using Xunit;

namespace AegisPC.Tests
{
    public class EventPatternMatcherTests
    {
        [Theory]
        [InlineData(1000, "Application Error", CrashEventType.AppCrash)]
        [InlineData(1002, "Application Hang", CrashEventType.AppHang)]
        [InlineData(41, "Microsoft-Windows-Kernel-Power", CrashEventType.UnexpectedShutdown)]
        [InlineData(1001, "BugCheck", CrashEventType.BSOD)]
        public void MatchCrashEvent_StandardEvent_ReturnsMatchingType(int eventId, string provider, CrashEventType expectedType)
        {
            var entry = new WindowsEventEntry
            {
                EventId = eventId,
                ProviderName = provider,
                Message = "Faulting application test.exe"
            };

            var crash = EventPatternMatcher.MatchCrashEvent(entry);

            Assert.NotNull(crash);
            Assert.Equal(expectedType, crash!.EventType);
        }

        [Fact]
        public void MatchCrashEvent_NonCrashEvent_ReturnsNull()
        {
            var entry = new WindowsEventEntry
            {
                EventId = 7036,
                ProviderName = "Service Control Manager",
                Message = "The service entered the running state."
            };

            var crash = EventPatternMatcher.MatchCrashEvent(entry);

            Assert.Null(crash);
        }
    }
}
