using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface ISignatureVerifier
{
    Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default);
}
