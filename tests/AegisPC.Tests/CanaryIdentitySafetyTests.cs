using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AegisPC.Core.Helpers;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests;

/// <summary>
/// Exercises decoy ownership using only harmless files in unique temporary roots. No configured protected root,
/// real process, Defender setting, network share, reparse point or installed application is accessed.
/// </summary>
public sealed class CanaryIdentitySafetyTests
{
    /// <summary>Existing documents with both decoy names retain their bytes and attributes across deployment and cleanup.</summary>
    [Fact]
    public void ExistingUserDocuments_AreNeverAdoptedHiddenOrDeleted()
    {
        using var fixture = new CanaryFixture();
        var documents = CanaryTrapManager.CanaryFileNames.Select(name =>
            fixture.CreateUserFile(name, "Harmless user document: " + name)).ToArray();
        var attributes = documents.Select(File.GetAttributes).ToArray();
        var contents = documents.Select(File.ReadAllBytes).ToArray();

        fixture.Manager.DeployCanaries([fixture.Root]);

        Assert.Empty(fixture.Manager.CanaryFiles);
        Assert.All(documents, path => Assert.False(fixture.Manager.IsCanaryPath(path)));
        fixture.Manager.CleanupCanaries();
        for (int index = 0; index < documents.Length; index++)
        {
            Assert.Equal(contents[index], File.ReadAllBytes(documents[index]));
            Assert.Equal(attributes[index], File.GetAttributes(documents[index]));
        }
    }

    /// <summary>A collision at one name leaves the user file untouched and permits exclusive creation at the other name.</summary>
    [Fact]
    public void OneExistingUserDocument_CleanupRemovesOnlyNewlyCreatedDecoy()
    {
        using var fixture = new CanaryFixture();
        string userDocument = fixture.CreateUserFile(CanaryTrapManager.CanaryFileName, "User-owned notes.");
        FileAttributes userAttributes = File.GetAttributes(userDocument);
        string createdDecoy = Path.Combine(fixture.Root, CanaryTrapManager.SecondaryCanaryFileName);

        fixture.Manager.DeployCanaries([fixture.Root]);

        Assert.Equal(createdDecoy, Assert.Single(fixture.Manager.CanaryFiles));
        Assert.True(fixture.Manager.IsCanaryPath(createdDecoy));
        Assert.False(fixture.Manager.IsCanaryPath(userDocument));
        Assert.True((File.GetAttributes(createdDecoy) & FileAttributes.Hidden) != 0);
        fixture.Manager.CleanupCanaries();
        Assert.False(File.Exists(createdDecoy));
        Assert.Equal("User-owned notes.", File.ReadAllText(userDocument));
        Assert.Equal(userAttributes, File.GetAttributes(userDocument));
        Assert.Equal(0, fixture.Manager.CanaryFileCount);
        Assert.False(fixture.Manager.IsCleaningUpCanaries);
    }

    /// <summary>Another root and decoy-like filenames never become observations through name inference.</summary>
    [Fact]
    public void SameFilenameElsewhere_AndLookalikeNames_AreNotCanaryPaths()
    {
        using var fixture = new CanaryFixture();
        using var otherRoot = new CanaryFixture();
        fixture.Manager.DeployCanaries([fixture.Root]);
        Assert.Equal(2, fixture.Manager.CanaryFileCount);
        string otherDocument = otherRoot.CreateUserFile(CanaryTrapManager.CanaryFileName, "Independent user document.");

        Assert.False(fixture.Manager.IsCanaryPath(otherDocument));
        Assert.False(fixture.Manager.IsCanaryPath(Path.Combine(fixture.Root, "ordinary_ultron_shield_canary.docx")));
        Assert.False(fixture.Manager.IsCanaryPath(Path.Combine(fixture.Root, "ordinary_ultron_canary.docx")));
        Assert.False(fixture.Manager.IsCanaryPath(Path.Combine(fixture.Root, CanaryTrapManager.CanaryFileName + ".extra")));
    }

    /// <summary>A replacement at an owned path remains an observation only; cleanup cannot delete or alter its new identity.</summary>
    [Fact]
    public void ReplacedCanaryIdentity_IsNotChangedOrDeleted()
    {
        using var fixture = new CanaryFixture();
        fixture.Manager.DeployCanaries([fixture.Root]);
        string path = Path.Combine(fixture.Root, CanaryTrapManager.CanaryFileName);
        string movedOriginal = fixture.TrackFile("moved-original.tmp");
        // Keep the original object alive so the filesystem cannot reuse its identity for the replacement.
        File.Move(path, movedOriginal);
        fixture.CreateUserFile(CanaryTrapManager.CanaryFileName, "Replacement user document.");
        File.SetAttributes(path, FileAttributes.Archive | FileAttributes.ReadOnly);
        FileAttributes replacementAttributes = File.GetAttributes(path);

        Assert.True(fixture.Manager.IsCanaryPath(path));
        fixture.Manager.CleanupCanaries();

        Assert.Equal("Replacement user document.", File.ReadAllText(path));
        Assert.Equal(replacementAttributes, File.GetAttributes(path));
        Assert.True(File.Exists(movedOriginal));
        Assert.False(File.Exists(Path.Combine(fixture.Root, CanaryTrapManager.SecondaryCanaryFileName)));
        Assert.Empty(fixture.Manager.CanaryFiles);
        Assert.False(fixture.Manager.IsCanaryPath(path));
    }

    /// <summary>Repeated and duplicate deployment preserves live decoys without rewriting them or duplicating records.</summary>
    [Fact]
    public void RepeatedDeployment_PreservesLiveOwnershipAndCount()
    {
        using var fixture = new CanaryFixture();
        fixture.Manager.DeployCanaries([fixture.Root]);
        string[] paths = fixture.Manager.CanaryFiles.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
        var writeTimes = paths.Select(File.GetLastWriteTimeUtc).ToArray();
        Assert.Equal(2, paths.Length);

        fixture.Manager.DeployCanaries([fixture.Root, fixture.Root]);
        fixture.Manager.DeployCanaries(Array.Empty<string>());

        Assert.Equal(paths, fixture.Manager.CanaryFiles.OrderBy(path => path, StringComparer.OrdinalIgnoreCase));
        Assert.Equal(writeTimes, paths.Select(File.GetLastWriteTimeUtc));
        Assert.Equal(2, fixture.Manager.CanaryFileCount);
        fixture.Manager.CleanupCanaries();
        Assert.All(paths, path => Assert.False(File.Exists(path)));
    }

    /// <summary>A missing recorded path is exclusively recreated with a new identity that can subsequently be cleaned up.</summary>
    [Fact]
    public void RecreatedDecoy_ReceivesFreshOwnershipRecord()
    {
        using var fixture = new CanaryFixture();
        fixture.Manager.DeployCanaries([fixture.Root]);
        string path = Path.Combine(fixture.Root, CanaryTrapManager.CanaryFileName);
        string movedOriginal = fixture.TrackFile("previous-owned-object.tmp");
        File.Move(path, movedOriginal);

        fixture.Manager.DeployCanaries([fixture.Root]);

        Assert.True(File.Exists(path));
        Assert.True(fixture.Manager.IsCanaryPath(path));
        Assert.Equal(2, fixture.Manager.CanaryFileCount);
        fixture.Manager.CleanupCanaries();
        Assert.False(File.Exists(path));
        Assert.True(File.Exists(movedOriginal));
        Assert.Empty(fixture.Manager.CanaryFiles);
    }

    /// <summary>A new manager does not infer ownership of an earlier manager's on-disk decoys.</summary>
    [Fact]
    public void NewManager_DoesNotAdoptExistingDecoysFromAnotherInstance()
    {
        using var fixture = new CanaryFixture();
        fixture.Manager.DeployCanaries([fixture.Root]);
        string[] paths = fixture.Manager.CanaryFiles.ToArray();
        var otherManager = new CanaryTrapManager();

        otherManager.DeployCanaries([fixture.Root]);
        otherManager.CleanupCanaries();

        Assert.Empty(otherManager.CanaryFiles);
        Assert.All(paths, path => Assert.True(File.Exists(path)));
        Assert.All(paths, path => Assert.False(otherManager.IsCanaryPath(path)));
    }

    /// <summary>UNC fixtures fail at syntax routing before metadata readers, deployment or any native file handle is requested.</summary>
    [Theory]
    [InlineData(@"\\server.invalid\share\folder")]
    [InlineData(@"\\?\UNC\server.invalid\share\folder")]
    public void NetworkSyntax_IsRejectedBeforeCanaryIo(string path)
    {
        Assert.False(ImplicitLocalPathPolicy.IsEligible(path,
            _ => throw new InvalidOperationException("Network drive metadata was not authorized."),
            _ => throw new InvalidOperationException("Network path metadata was not authorized.")));
        var manager = new CanaryTrapManager();

        manager.DeployCanaries([path]);
        manager.CleanupCanaries();

        Assert.Empty(manager.CanaryFiles);
        Assert.False(manager.IsCanaryPath(Path.Combine(path, CanaryTrapManager.CanaryFileName)));
    }

    private sealed class CanaryFixture : IDisposable
    {
        private readonly HashSet<string> _createdFiles = new(StringComparer.OrdinalIgnoreCase);
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "Ultron_Canary_Identity_" + Guid.NewGuid().ToString("N"));
        public CanaryTrapManager Manager { get; } = new();

        public CanaryFixture()
        {
            Assert.True(ImplicitLocalPathPolicy.IsEligible(Root));
            Directory.CreateDirectory(Root);
            foreach (string name in CanaryTrapManager.CanaryFileNames) TrackFile(name);
        }

        public string TrackFile(string name)
        {
            string path = Path.Combine(Root, name);
            _createdFiles.Add(path);
            return path;
        }

        public string CreateUserFile(string name, string content)
        {
            string path = TrackFile(name);
            File.WriteAllText(path, content);
            return path;
        }

        public void Dispose()
        {
            Manager.CleanupCanaries();
            // Remove only explicit fixture files within this GUID root; unexpected files prevent directory removal.
            foreach (string path in _createdFiles)
            {
                Assert.Equal(Root, Path.GetDirectoryName(path));
                if (!File.Exists(path)) continue;
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
            }
            Directory.Delete(Root, recursive: false);
        }
    }
}
