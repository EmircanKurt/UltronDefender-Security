using AegisPC.Core.Helpers;
using Xunit;

namespace AegisPC.Tests
{
    public class PathHelperTests
    {
        [Fact]
        public void CanonicalizePath_TrailingSlash_Normalized()
        {
            var raw = @"C:\Windows\System32\";
            var normalized = PathHelper.CanonicalizePath(raw);
            Assert.Equal(@"C:\Windows\System32", normalized);
        }

        [Fact]
        public void ValidateFilePath_InvalidChars_ReturnsFalse()
        {
            Assert.False(PathHelper.ValidateFilePath("C:\\test\\<invalid>.txt"));
            Assert.False(PathHelper.ValidateFilePath(""));
        }
    }
}
