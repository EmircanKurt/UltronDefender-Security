using System;

namespace AegisPC.Contracts.Safety
{
    /// <summary>
    /// NTFS Symlink / Junction / Reparse Point hedef ve güvenlik bilgisi.
    /// </summary>
    public class ReparsePointInfo
    {
        public string Path { get; set; } = string.Empty;
        public bool IsReparsePoint { get; set; }
        public ReparsePointType Type { get; set; } = ReparsePointType.None;
        public string? TargetPath { get; set; }
        public string? PrintName { get; set; }
        public bool PointsToProtectedTarget { get; set; }
        public bool IsCrossBoundaryTrap { get; set; }

        public override string ToString() => $"[ReparsePoint: {IsReparsePoint}, Type: {Type}, Target: '{TargetPath}', ProtectedTarget: {PointsToProtectedTarget}]";
    }
}
