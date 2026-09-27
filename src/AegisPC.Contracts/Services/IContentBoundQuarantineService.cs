using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services;

/// <summary>Contains only the file content that was positively identified by a detector.</summary>
public interface IContentBoundQuarantineService
{
    /// <summary>Returns false without deleting the source when its locked SHA-256 differs from the detected content.</summary>
    Task<bool> TryQuarantineFileAsync(string path, string reason, string expectedSha256,
        CancellationToken cancellationToken = default);
}
