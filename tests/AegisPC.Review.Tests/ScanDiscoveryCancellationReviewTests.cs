using System.IO;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Exercises actual enumeration of inert temporary files, without process inventory or detectors.</summary>
public sealed class ScanDiscoveryCancellationReviewTests
{
    /// <summary>Cancellation after a dispatch must not return a successful completed enumeration.</summary>
    [Fact]
    public async Task MidWalkCancellationIsNotSuccess()
    {
        string root = Path.Combine(Path.GetTempPath(), "UltronDiscoveryReview", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            File.WriteAllText(Path.Combine(root, "inert.bin"), "inert");
            using var cancellation = new CancellationTokenSource();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new DirectoryWalker().EnumerateDirectorySafelyAsync(
                root, true, _ => { cancellation.Cancel(); return Task.CompletedTask; }, cancellation.Token));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    /// <summary>A failed consumer cannot be swallowed as an unrelated directory access error.</summary>
    [Fact]
    public async Task ConsumerFailureIsNotSuccessfulEnumeration()
    {
        string root = Path.Combine(Path.GetTempPath(), "UltronDiscoveryReview", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            File.WriteAllText(Path.Combine(root, "inert.bin"), "inert");
            var failure = await Assert.ThrowsAnyAsync<Exception>(() => new DirectoryWalker().EnumerateDirectorySafelyAsync(
                root, true, _ => throw new IOException("Inert consumer failure"), CancellationToken.None));
            Assert.IsType<IOException>(failure.InnerException);
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
