using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

/// <summary>Identifies bounded file structures without relying on names or executing content.</summary>
public interface IFileContentClassifier
{
    /// <summary>
    /// Reads a caller-owned, seekable source and restores its position. The caller must hold a stable read lock
    /// across classification and detection; unsupported or malformed input returns explicit coverage limits.
    /// Cancellation and source I/O failures propagate and cannot establish a clean verdict.
    /// </summary>
    Task<FileContentClassification> ClassifyAsync(Stream source, string declaredExtension, CancellationToken cancellationToken = default);
}
