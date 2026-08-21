using AegisPC.Core.Constants;
using Xunit;

namespace AegisPC.Tests
{
    public class CriticalProcessesTests
    {
        [Theory]
        [InlineData("csrss.exe", true)]
        [InlineData("csrss", true)]
        [InlineData("lsass.exe", true)]
        [InlineData("services.exe", true)]
        [InlineData("smss.exe", true)]
        [InlineData("wininit.exe", true)]
        [InlineData("notepad.exe", false)]
        [InlineData("chrome.exe", false)]
        [InlineData("malware.exe", false)]
        public void IsCriticalProcess_ShouldCorrectlyIdentifyProtectedProcesses(string processName, bool expected)
        {
            bool isCritical = CriticalProcesses.IsCriticalProcess(processName);
            Assert.Equal(expected, isCritical);
        }
    }
}
