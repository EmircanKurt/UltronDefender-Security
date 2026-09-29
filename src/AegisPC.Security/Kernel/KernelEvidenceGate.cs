using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;

namespace AegisPC.Security.Kernel;

/// <summary>
/// Checks whether a pre-operation detection is tied to the current file content.
/// Heuristic scores and product-directory membership never authorize a block.
/// </summary>
public static class KernelEvidenceGate
{
    /// <summary>
    /// Requires a complete confirmed verdict, absolute static evidence, and a matching
    /// SHA-256 of the currently opened file. I/O failures and cancellation are propagated
    /// to the caller so its pre-operation fail-open policy can avoid a false block.
    /// </summary>
    /// <param name="result">Detection verdict and evidence from the shared hub.</param>
    /// <param name="filePath">File to verify without modifying it.</param>
    /// <param name="cancellationToken">Pre-operation time budget.</param>
    /// <returns>True only when all confirmation and content checks pass.</returns>
    public static async Task<bool> HasCurrentAbsoluteSignatureAsync(
        DetectionResult? result, string filePath, CancellationToken cancellationToken = default)
    {
        if (result?.Verdict != DetectionVerdict.ConfirmedMalicious ||
            !result.IsComplete || result.FailedDetectorCount != 0 ||
            string.IsNullOrWhiteSpace(filePath) ||
            !result.Evidences.Any(e => e.Category == EvidenceCategory.StaticSignature &&
                e.Confidence == EvidenceConfidence.Absolute && e.ScoreContribution >= 80))
        {
            return false;
        }

        string expectedHex = result.SHA256 ?? string.Empty;
        if (expectedHex.Length != 64 || !expectedHex.All(Uri.IsHexDigit)) return false;

        byte[] expected = Convert.FromHexString(expectedHex);
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read | FileShare.Delete, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        byte[] actual = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
