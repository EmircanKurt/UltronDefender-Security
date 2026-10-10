using System.IO;
using System.Reflection;
using System.Xml.Linq;
using AegisPC.Service.Update;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Checks source-level laboratory opt-in and endpoint API boundaries without running legacy host-mutating fixtures.</summary>
public sealed class LabTestGateReviewTests
{
    /// <summary>Checks the explicit default-off compile exclusions and independent lab acknowledgement; this does not certify a real VM.</summary>
    [Fact]
    public void LiveHostFixturesRequireExplicitLabCompileOptIn()
    {
        var root = FindRepositoryRoot();
        var project = XDocument.Load(Path.Combine(root, "tests", "AegisPC.Tests", "AegisPC.Tests.csproj"));
        var defaultSetting = Assert.Single(project.Descendants("EnableUnsafeLabTests"));
        Assert.Equal("false", defaultSetting.Value);
        Assert.Equal("'$(EnableUnsafeLabTests)' == ''", defaultSetting.Attribute("Condition")?.Value);
        var exclusions = Assert.Single(project.Descendants("ItemGroup").Where(group =>
            group.Attribute("Condition")?.Value == "'$(EnableUnsafeLabTests)' != 'true'"));
        var excluded = exclusions.Elements("Compile").Select(item => item.Attribute("Remove")?.Value).ToHashSet();
        string[] expected = ["RealBrowserAndStressValidationTests.cs", "LiveSampleTests.cs",
            "RansomwareRealProcessKillTests.cs", "RansomwareShieldTests.cs", "RealTimeProtectionTests.cs",
            "SelfProtectionTests.cs", "LiveEndpointHardeningTests.cs", "EtwPreExecProtectionTests.cs",
            "DnsFilterTest.cs", "OfflineDnsAndUrlFilteringTests.cs"];
        Assert.Equal(expected.Length, excluded.Count);
        foreach (var file in expected) Assert.Contains(file, excluded);
        var gate = Assert.Single(project.Descendants("Target").Where(target =>
            target.Attribute("Name")?.Value == "ValidateUnsafeLabOptIn"));
        Assert.Equal("'$(EnableUnsafeLabTests)' == 'true'", gate.Attribute("Condition")?.Value);
        Assert.Equal("CoreCompile", gate.Attribute("BeforeTargets")?.Value);
        Assert.Equal("'$(UltronIsolatedLabAcknowledged)' != 'true'",
            Assert.Single(gate.Elements("Error")).Attribute("Condition")?.Value);
    }

    /// <summary>Ensures a provider's family label cannot be converted into an endpoint exact-malware category by the removed API.</summary>
    [Fact]
    public void EndpointDoesNotExposeFamilyLabelAsDetection()
    {
        Assert.Null(typeof(ThreatFeedUpdater).GetMethod("DetectCategory", BindingFlags.Public | BindingFlags.Static));
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "AegisPC.sln"))) return directory.FullName;
        throw new DirectoryNotFoundException("Repository root was not found for source policy inspection.");
    }
}
