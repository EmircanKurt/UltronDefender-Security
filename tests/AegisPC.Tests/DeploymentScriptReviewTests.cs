using System.IO;
using System.Runtime.InteropServices;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Source and OS argument-decoding tests only; installer scripts are never executed.</summary>
public sealed class DeploymentScriptReviewTests
{
    [Theory]
    [InlineData("install.ps1")]
    [InlineData("scripts/install.ps1")]
    public void OrdinaryInstaller_DoesNotInstallKernelDriverAndUsesCanonicalServiceName(string relativePath)
    {
        var script = File.ReadAllText(Path.Combine(RepositoryRoot(), relativePath));
        Assert.DoesNotContain("& pnputil.exe", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("& fltmc.exe load", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("$ServiceName        = \"AegisPC Protection Service\"", script);
        Assert.Contains("New-Service -Name $ServiceName -BinaryPathName $binPathArg", script);
    }

    [Fact]
    public void PreviewInno_DoesNotInstallOrStartNativeServices()
    {
        var script = File.ReadAllText(Path.Combine(RepositoryRoot(), "installer.iss"));
        Assert.Contains("PrivilegesRequired=lowest", script);
        Assert.DoesNotContain("Filename: \"{sys}\\sc.exe\"", script);
        Assert.DoesNotContain("Tasks: installservice", script);
        Assert.DoesNotContain("Root: HKLM", script);
        Assert.DoesNotContain("postinstall", script);
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "AegisPC.sln"))) directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Test checkout could not be located.");
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
