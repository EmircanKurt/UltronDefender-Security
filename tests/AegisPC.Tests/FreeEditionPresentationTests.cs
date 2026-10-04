using System.IO;
using System.Reflection;
using AegisPC.App.ViewModels;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Checks the free edition's presentation surface without constructing the app or starting protection services.</summary>
public sealed class FreeEditionPresentationTests
{
    /// <summary>Rejects the old sample license and expiry properties and their generated clipboard command.</summary>
    [Fact]
    public void Dashboard_DoesNotExposeSampleLicensePropertiesOrCommands()
    {
        var dashboardType = typeof(DashboardViewModel);
        const BindingFlags flags = BindingFlags.Public | BindingFlags.Instance;
        Assert.Null(dashboardType.GetProperty("LicenseKey", flags));
        Assert.Null(dashboardType.GetProperty("LicenseExpires", flags));
        Assert.Null(dashboardType.GetProperty("CopyLicenseKeyCommand", flags));
        Assert.Null(dashboardType.GetMethod("CopyLicenseKey", flags));
    }

    /// <summary>Inspects every source App XAML file so no page retains a binding to the removed licensing surface.</summary>
    [Fact]
    public void AppXaml_DoesNotReferenceSampleLicensePresentation()
    {
        var appDirectory = Path.Combine(RepositoryRoot(), "src", "AegisPC.App");
        var xamlFiles = Directory.EnumerateFiles(appDirectory, "*.xaml", SearchOption.AllDirectories)
            .Where(path => !Path.GetRelativePath(appDirectory, path)
                .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Any(segment => segment.Equals("bin", StringComparison.OrdinalIgnoreCase) ||
                    segment.Equals("obj", StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        Assert.NotEmpty(xamlFiles);
        foreach (var path in xamlFiles)
        {
            var markup = File.ReadAllText(path);
            Assert.DoesNotContain("LicenseKey", markup, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("LicenseExpires", markup, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("CopyLicenseKey", markup, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "AegisPC.sln")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Test checkout could not be located.");
    }
}
