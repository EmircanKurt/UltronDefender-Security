using System;
using System.Collections.Generic;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class FileAnalysisResult
{
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string? SHA256 { get; set; }
    public string? SHA1 { get; set; }
    public long FileSize { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ModifiedAt { get; set; }
    public bool IsSigned { get; set; }
    public string? SignaturePublisher { get; set; }
    public bool SignatureValid { get; set; }
    public bool IsExecutable { get; set; }
    public string? ExecutableType { get; set; }
    public double Entropy { get; set; }
    public bool IsKnownLocation { get; set; }
    public bool IsPacked { get; set; }
    public string? PackerName { get; set; }
    public int RiskScore { get; set; }
    public List<string> RiskReasons { get; set; } = new();
    public RiskLevel RiskLevel { get; set; }
    public ConfidenceLevel ConfidenceLevel { get; set; }
}
