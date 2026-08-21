using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IFileScanner
{
    Task<SecurityFinding?> ScanFileAsync(string path, CancellationToken cancellationToken = default);
    Task<ScanResult> ScanDirectoryAsync(string path, ScanType scanType, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default);
}
