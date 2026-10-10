using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>Enumerates local volumes by native GUID, including ready volumes that have no drive letter.</summary>
public sealed class WindowsScanVolumeTargetResolver : IScanVolumeTargetResolver
{
    /// <inheritdoc />
    public Task<ScanVolumeTargetResolution> ResolveAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var gaps = new HashSet<string>(StringComparer.Ordinal);
        var buffer = new StringBuilder(1024);
        IntPtr search = FindFirstVolumeW(buffer, buffer.Capacity);
        if (search == new IntPtr(-1)) return Task.FromResult(new ScanVolumeTargetResolution { Limitations = ["LocalVolumeInventoryUnavailable"] });
        try
        {
            int count = 0;
            do
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++count > 4096) { gaps.Add("LocalVolumeInventoryBudgetExceeded"); break; }
                string root = buffer.ToString();
                if (!root.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase) || !root.EndsWith(@"}\", StringComparison.Ordinal))
                { gaps.Add("InvalidNativeVolumeIdentity"); continue; }
                uint type = GetDriveTypeW(root);
                if (type is 0 or 1) { gaps.Add("LocalVolumeTypeUnresolved"); continue; }
                if (type is not (2 or 3)) continue; // Remote, optical and RAM disks are not implicitly selected.
                if (!GetVolumeInformationW(root, null, 0, out _, out _, out _, null, 0))
                { gaps.Add("LocalVolumeNotReadyOrAccessible"); continue; }
                roots.Add(root);
            } while (FindNextVolumeW(search, buffer, buffer.Capacity));
            if (count <= 4096 && Marshal.GetLastWin32Error() != 18) gaps.Add("LocalVolumeEnumerationInterrupted");
        }
        finally { FindVolumeClose(search); }
        if (roots.Count == 0) gaps.Add("NoReadyLocalVolumesResolved");
        return Task.FromResult(new ScanVolumeTargetResolution { VolumeRoots = [.. roots], Limitations = [.. gaps] });
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr FindFirstVolumeW(StringBuilder name, int length);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindNextVolumeW(IntPtr search, StringBuilder name, int length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindVolumeClose(IntPtr search);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationW(string root, StringBuilder? name, int nameLength,
        out uint serial, out uint maxComponentLength, out uint flags, StringBuilder? fileSystem, int fileSystemLength);
}
