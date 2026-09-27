using System;
using System.IO;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Checks installer source boundaries only; does not execute installation or change Windows services.</summary>
public sealed class InstallerWorkflowTests
{
    [Fact]
    public void Installer_AdvertisesRealRepositoryAndSupportedOs()
    {
        string source = Read("installer.iss");
        Assert.Contains("https://github.com/EmircanKurt/UltronDefender-Security", source);
        Assert.Contains("MinVersion=10.0.17763", source);
        Assert.Contains("ArchitecturesAllowed=x64compatible", source);
        Assert.Contains("#define MyAppVersion \"3.2.1\"", source);
    }

    [Fact]
    public void Installer_UsesExplicitPortableStagingNotDeveloperMachinePath()
    {
        string source = Read("installer.iss");
        Assert.Contains("{#AppPublishDir}", source);
        Assert.DoesNotContain("c:\\Users\\PC\\Documents", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Uninstall_DoesNotDeleteUnknownFilesOrKillProcessesByName()
    {
        string source = Read("installer.iss");
        Assert.DoesNotContain("Type: filesandordirs; Name: \"{app}\"", source);
        Assert.DoesNotContain("taskkill.exe", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_DefaultUsesBenignTestsAndDoesNotModifyDesktop()
    {
        string source = Read("build_and_deploy.ps1");
        Assert.Contains("AegisPC.Review.Tests", source);
        Assert.Contains("FullyQualifiedName!~Golden01_", source);
        Assert.Contains("if ($UpdateDesktopShortcut)", source);
        Assert.Contains("throw \"Inno Setup compilation failed", source);
        Assert.Contains("$PSScriptRoot", source);
    }

    private static string Read(string file)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "AegisPC.sln"))) return File.ReadAllText(Path.Combine(directory.FullName, file));
        throw new DirectoryNotFoundException("Repository root was not found.");
    }
}
