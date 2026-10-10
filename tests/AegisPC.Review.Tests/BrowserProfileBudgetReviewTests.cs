using System.IO;
using AegisPC.BrowserSecurity.Browser;
using AegisPC.Core.Enums;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Benign temporary metadata fixture for combined profile quotas; no installed browser is queried.</summary>
public sealed class BrowserProfileBudgetReviewTests
{
    /// <summary>The root-profile candidate cannot silently disappear when Default and numbered profiles fill the quota.</summary>
    [Fact]
    public void RootProfileBeyondBudgetIsReportedAsPartial()
    {
        string root = Path.Combine(Path.GetTempPath(), "ultron-profile-budget-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(root);
            const string preferences = "{\"extensions\":{\"settings\":{}}}";
            File.WriteAllText(Path.Combine(root, "Preferences"), preferences);
            foreach (var name in new[] { "Default" }.Concat(Enumerable.Range(1, 63).Select(index => "Profile " + index)))
            {
                string profile = Path.Combine(root, name);
                Directory.CreateDirectory(profile);
                File.WriteAllText(Path.Combine(profile, "Preferences"), preferences);
            }
            var snapshot = ChromiumExtensionScanner.ScanInventory(root, BrowserType.Chrome);
            Assert.Equal(64, snapshot.Profiles.Count);
            Assert.Equal(BrowserInventoryCoverage.Partial, snapshot.Coverage);
            Assert.Contains(snapshot.Issues, issue => issue.Code == "ProfileLimitExceeded");
            Assert.DoesNotContain(snapshot.Profiles, profile => profile.Profile.ProfilePath == root);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }
}
