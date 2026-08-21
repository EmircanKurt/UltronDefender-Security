using System;

namespace AegisPC.Contracts.Safety
{
    /// <summary>
    /// Dosya veya dizin yolu için koruma ve kritiklik değerlendirme sonucu.
    /// </summary>
    public class ProtectedPathEvaluation
    {
        public string OriginalPath { get; set; } = string.Empty;
        public string CanonicalPath { get; set; } = string.Empty;
        public bool IsProtected { get; set; }
        public bool IsCriticalSystemCore { get; set; }
        public ProtectedPathCategory Category { get; set; } = ProtectedPathCategory.None;
        public string Reason { get; set; } = string.Empty;

        public override string ToString() => $"[Protected: {IsProtected}, Critical: {IsCriticalSystemCore}, Cat: {Category}] {Reason}";
    }
}
