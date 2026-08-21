using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services
{
    public interface IScanCoordinatorService
    {
        bool IsScanning { get; }
        ScanType CurrentScanType { get; }
        double ProgressPercent { get; }
        string CurrentFile { get; }
        int ScannedFiles { get; }
        int TotalFiles { get; }
        int FindingsCount { get; }
        string StatusText { get; }
        IReadOnlyList<SecurityFinding> CurrentFindings { get; }

        event Action<ScanProgress>? ProgressChanged;
        event Action<ScanResult>? ScanCompleted;

        Task<ScanResult?> StartScanAsync(ScanType scanType, string customPath = "");
        void CancelScan();
    }
}
