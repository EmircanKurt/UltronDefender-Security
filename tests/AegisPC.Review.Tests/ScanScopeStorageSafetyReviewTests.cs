using System;
using AegisPC.Core.Helpers;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Pure scope/device normalization checks; no live drive, process or registry inventory.</summary>
public sealed class ScanScopeStorageSafetyReviewTests
{
    /// <summary>Drive-letter and GUID paths resolve without treating a local GUID volume as network storage.</summary>
    [Theory]
    [InlineData(@"C:\Windows\file.dll", @"\\.\C:")]
    [InlineData(@"d:\", @"\\.\D:")]
    [InlineData(@"\\?\Volume{12345678-1234-1234-1234-123456789abc}\folder\file", @"\\?\Volume{12345678-1234-1234-1234-123456789abc}")]
    public void LocalDeviceRoot_IsNormalized(string path, string expected) => Assert.Equal(expected, DiskHardwareHelper.ResolveVolumeDevicePath(path));

    /// <summary>Unknown, remote and arbitrary device routes cannot be opened by the classifier.</summary>
    [Theory]
    [InlineData(@"\\server\share\file")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"C:relative")]
    [InlineData(@"\\?\Volume{not-guid}\file")]
    [InlineData(@"\\?\Volume{12345678-1234-1234-1234-123456789abc}suffix")]
    [InlineData("relative")]
    public void UntrustedDeviceRoute_IsRejected(string path)
    {
        Assert.Null(DiskHardwareHelper.ResolveVolumeDevicePath(path));
        Assert.Equal(DiskHardwareHelper.StorageSeekKind.Unknown, DiskHardwareHelper.GetSeekKind(path));
    }

    /// <summary>Quick scope includes either new or recently modified content, including uncertain timestamps.</summary>
    [Theory]
    [InlineData(1, 50, true)]
    [InlineData(50, 1, true)]
    [InlineData(7, 50, true)]
    [InlineData(50, 50, false)]
    [InlineData(-1, 50, true)]
    public void RecentScope_IsNotAnExtensionOrTrustExemption(int createdDays, int modifiedDays, bool included)
    {
        var now = new DateTime(2026, 10, 9, 12, 0, 0, DateTimeKind.Utc);
        Assert.Equal(included, QuickScanRecencyPolicy.ShouldInspect(now.AddDays(-createdDays), now.AddDays(-modifiedDays), now));
        Assert.True(QuickScanRecencyPolicy.ShouldInspect(DateTime.MinValue, now.AddDays(-50), now));
    }
}
