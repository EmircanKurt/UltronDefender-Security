using System.IO;
using System.Reflection;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert implicit-path decisions; network fixtures never call native APIs or access a share.</summary>
public sealed class ImplicitLocalPathPolicyTests
{
    /// <summary>Non-local namespaces and ambiguous syntax are rejected before any injected metadata query.</summary>
    [Theory]
    [InlineData(@"\\server.invalid\share\folder")]
    [InlineData(@"\\?\UNC\server.invalid\share")]
    [InlineData(@"\\.\C:\folder")]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolume1\folder")]
    [InlineData(@"C:relative")]
    [InlineData(@"relative\file")]
    [InlineData(@"C:\folder\payload:stream")]
    [InlineData(@"C:\folder\..\file")]
    [InlineData(@"\\?\Volume{invalid}\folder")]
    [InlineData(@"C:\folder\*.exe")]
    public void UnsafeSyntax_DoesNotInvokeMetadataReaders(string path)
    {
        Assert.False(ImplicitLocalPathPolicy.HasLocalSyntax(path));
        Assert.False(ImplicitLocalPathPolicy.IsEligible(path,
            _ => throw new InvalidOperationException("No drive query was authorized."),
            _ => throw new InvalidOperationException("No path I/O was authorized.")));
    }

    /// <summary>Local syntax includes volume-GUID and extended-drive roots, including non-ASCII names.</summary>
    [Theory]
    [InlineData(@"C:\School\Öğrenci\Downloads", @"C:\")]
    [InlineData(@"E:\", @"E:\")]
    [InlineData(@"\\?\C:\local\file", @"\\?\C:\")]
    [InlineData(@"\\?\Volume{11111111-1111-1111-1111-111111111111}\folder",
        @"\\?\Volume{11111111-1111-1111-1111-111111111111}\")]
    public void LocalSyntax_UsesOnlyItsExplicitRoot(string path, string expectedRoot)
    {
        Assert.True(ImplicitLocalPathPolicy.HasLocalSyntax(path));
        Assert.True(ImplicitLocalPathPolicy.IsEligible(path, root =>
        { Assert.Equal(expectedRoot, root); return DriveType.Fixed; }, _ => FileAttributes.Directory));
    }

    /// <summary>A drive-letter spelling is not evidence of local storage; unavailable/remote types make no attribute requests.</summary>
    [Theory]
    [InlineData(DriveType.Unknown)]
    [InlineData(DriveType.NoRootDirectory)]
    [InlineData(DriveType.Network)]
    [InlineData(DriveType.CDRom)]
    public void NonLocalDrive_DoesNotReadAnyAncestor(DriveType type) =>
        Assert.False(ImplicitLocalPathPolicy.IsEligible(@"Z:\School\Desktop", _ => type,
            _ => throw new InvalidOperationException("No attribute access was authorized.")));

    /// <summary>Traversal stops at a reparse ancestor, before asking about a potentially remote child.</summary>
    [Fact]
    public void ReparseAncestor_StopsBeforeItsChild()
    {
        var queried = new List<string>();
        Assert.False(ImplicitLocalPathPolicy.IsEligible(@"C:\redirect\child", _ => DriveType.Fixed, path =>
        {
            queried.Add(path);
            return path == @"C:\redirect" ? FileAttributes.Directory | FileAttributes.ReparsePoint : FileAttributes.Directory;
        }));
        Assert.Equal(new[] { @"C:\", @"C:\redirect" }, queried);
    }

    /// <summary>Unavailable attributes are a coverage gap rather than permission to try a deeper target.</summary>
    [Fact]
    public void DeniedMetadata_FailsClosed() => Assert.False(ImplicitLocalPathPolicy.IsEligible(@"C:\denied\child",
        _ => DriveType.Fixed, _ => throw new UnauthorizedAccessException("inert denied metadata")));

    /// <summary>Implicit directory dispatch records omitted network coverage without starting process enumeration or network I/O.</summary>
    [Fact]
    public async Task ImplicitDirectory_RejectedBeforeEnumerationAndReportedPartial()
    {
        var coverage = new ScanCoverageSummary();
        var walker = new DirectoryWalker();
        using var scope = walker.BeginCoverage(coverage);
        int calls = 0;
        Func<string, Task> enqueue = _ => { calls++; return Task.CompletedTask; };
        var method = typeof(DirectoryWalker).GetMethod("EnumerateImplicitDirectoryAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        await (Task)method.Invoke(walker, [@"\\server.invalid\share", true, enqueue, CancellationToken.None, null])!;
        Assert.Equal(0, calls);
        Assert.False(coverage.IsComplete);
        Assert.Contains("ImplicitNonLocalOrReparseTargetNotInspected", coverage.Limitations);
    }
}
