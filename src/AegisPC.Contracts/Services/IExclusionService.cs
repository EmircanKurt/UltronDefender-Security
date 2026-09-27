using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services
{
    public interface IExclusionService
    {
        bool IsExcluded(string? filePath, string? sha256 = null);
        Task<bool> IsExcludedAsync(string? filePath, string? sha256 = null, CancellationToken cancellationToken = default);
        Task<IReadOnlyList<ExclusionEntry>> GetAllExclusionsAsync(CancellationToken cancellationToken = default);
        Task<ExclusionEntry> AddPathExclusionAsync(string path, bool includeSubdirectories = true, string? reason = null, CancellationToken cancellationToken = default);
        Task<ExclusionEntry> AddSha256ExclusionAsync(string sha256, string? reason = null, CancellationToken cancellationToken = default);
        void AddTemporaryPathExclusion(string path, TimeSpan duration, string? reason = null);
        // Implementations without content-bound support must fail closed, not fall back to a path exemption.
        void AddTemporaryContentExclusion(string path, string sha256, TimeSpan duration, string? reason = null) { }
        Task<bool> RemoveExclusionAsync(int id, CancellationToken cancellationToken = default);
        bool IsRootOrSystemDirectory(string path);
        Task InitializeAsync(CancellationToken cancellationToken = default);
    }
}
