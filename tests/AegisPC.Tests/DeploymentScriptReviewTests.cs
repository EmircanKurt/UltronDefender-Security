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
    public void InnoServiceImagePath_RemainsQuotedAfterWindowsArgumentDecoding()
    {
        var script = File.ReadAllLines(Path.Combine(RepositoryRoot(), "installer.iss"));
        var line = Assert.Single(script.Where(value => value.Contains("Parameters: \"create ", StringComparison.Ordinal)));
        const string start = "Parameters: \"";
        var begin = line.IndexOf(start, StringComparison.Ordinal) + start.Length;
        var end = line.IndexOf("\"; Flags:", begin, StringComparison.Ordinal);
        var parameters = line[begin..end].Replace("\"\"", "\"", StringComparison.Ordinal)
            .Replace("{app}", @"C:\Program Files\Review Fixture", StringComparison.Ordinal);
        var argumentPointer = CommandLineToArgvW("sc.exe " + parameters, out var count);
        Assert.NotEqual(IntPtr.Zero, argumentPointer);
        try
        {
            var arguments = Enumerable.Range(0, count).Select(index => Marshal.PtrToStringUni(
                Marshal.ReadIntPtr(argumentPointer, index * IntPtr.Size))).ToArray();
            Assert.Equal("AegisPC Protection Service", arguments[2]);
            var binIndex = Array.IndexOf(arguments, "binPath=");
            Assert.True(binIndex >= 0);
            Assert.Equal("\"C:\\Program Files\\Review Fixture\\Service\\AegisPC.Service.exe\"", arguments[binIndex + 1]);
        }
        finally { LocalFree(argumentPointer); }
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
