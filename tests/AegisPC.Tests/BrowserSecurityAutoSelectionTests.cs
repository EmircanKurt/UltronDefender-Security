using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Xunit;

namespace AegisPC.Tests
{
    public class BrowserSecurityAutoSelectionTests
    {
        private class FakeBrowserScanner : IBrowserSecurityScanner
        {
            private readonly List<BrowserProfile> _profiles;

            public FakeBrowserScanner(List<BrowserProfile> profiles)
            {
                _profiles = profiles;
            }

            public Task<List<BrowserProfile>> ScanAllBrowsersAsync(CancellationToken cancellationToken = default)
            {
                return Task.FromResult(_profiles);
            }

            public Task<BrowserProfile?> ScanBrowserAsync(BrowserType browserType, CancellationToken cancellationToken = default)
            {
                return Task.FromResult(_profiles.FirstOrDefault(p => p.BrowserType == browserType));
            }
        }

        [Fact]
        public async Task LoadBrowserDataAsync_AutomaticallySelectsProfileWithExtensions_OverEmptyProfiles()
        {
            // Arrange: Edge has 0 extensions, Brave has 3 extensions, Chrome has 1 extension
            var profiles = new List<BrowserProfile>
            {
                new BrowserProfile
                {
                    BrowserType = BrowserType.Edge,
                    ProfileName = "Default",
                    ProfilePath = "C:\\Edge\\Default",
                    Extensions = new List<BrowserExtension>() // 0 extensions
                },
                new BrowserProfile
                {
                    BrowserType = BrowserType.Brave,
                    ProfileName = "Default",
                    ProfilePath = "C:\\Brave\\Default",
                    Extensions = new List<BrowserExtension>
                    {
                        new BrowserExtension { Id = "ext1", Name = "UBlock Origin", Version = "1.50", RiskLevel = RiskLevel.LowRisk },
                        new BrowserExtension { Id = "ext2", Name = "Bitwarden", Version = "2024.1", RiskLevel = RiskLevel.LowRisk },
                        new BrowserExtension { Id = "ext3", Name = "Dark Reader", Version = "4.9", RiskLevel = RiskLevel.LowRisk }
                    }
                },
                new BrowserProfile
                {
                    BrowserType = BrowserType.Chrome,
                    ProfileName = "Default",
                    ProfilePath = "C:\\Chrome\\Default",
                    Extensions = new List<BrowserExtension>
                    {
                        new BrowserExtension { Id = "ext4", Name = "AdGuard", Version = "3.0", RiskLevel = RiskLevel.LowRisk }
                    }
                }
            };

            var fakeScanner = new FakeBrowserScanner(profiles);
            var vm = new BrowserSecurityViewModel(fakeScanner);

            // Act
            await vm.LoadBrowserDataAsync();

            // Assert: Brave (with 3 extensions) must be automatically selected over Edge (0 extensions)
            Assert.NotNull(vm.SelectedProfile);
            Assert.Equal(BrowserType.Brave, vm.SelectedProfile.BrowserType);
            Assert.Equal(3, vm.SelectedProfile.Extensions.Count);
            Assert.Equal(3, vm.Extensions.Count);
            Assert.False(vm.HasNoExtensions);
            Assert.NotNull(vm.SelectedExtension);
            Assert.Equal("ext1", vm.SelectedExtension.Id);

            // Assert: The profiles collection should order profiles with extensions first (Brave, Chrome, then Edge)
            Assert.Equal(BrowserType.Brave, vm.Profiles[0].BrowserType);
            Assert.Equal(BrowserType.Chrome, vm.Profiles[1].BrowserType);
            Assert.Equal(BrowserType.Edge, vm.Profiles[2].BrowserType);
        }

        [Fact]
        public async Task LoadBrowserDataAsync_WhenNoExtensionsInAnyBrowser_SelectsFirstProfileAndSetsHasNoExtensionsTrue()
        {
            // Arrange: All browsers have 0 extensions
            var profiles = new List<BrowserProfile>
            {
                new BrowserProfile
                {
                    BrowserType = BrowserType.Edge,
                    ProfileName = "Default",
                    ProfilePath = "C:\\Edge\\Default",
                    Extensions = new List<BrowserExtension>()
                },
                new BrowserProfile
                {
                    BrowserType = BrowserType.Chrome,
                    ProfileName = "Default",
                    ProfilePath = "C:\\Chrome\\Default",
                    Extensions = new List<BrowserExtension>()
                }
            };

            var fakeScanner = new FakeBrowserScanner(profiles);
            var vm = new BrowserSecurityViewModel(fakeScanner);

            // Act
            await vm.LoadBrowserDataAsync();

            // Assert
            Assert.NotNull(vm.SelectedProfile);
            Assert.True(vm.HasNoExtensions);
            Assert.Empty(vm.Extensions);
            Assert.Null(vm.SelectedExtension);
        }

        [Fact]
        public void BrowserProfile_DisplayText_ReturnsFormattedExtensionCount()
        {
            var p1 = new BrowserProfile
            {
                BrowserType = BrowserType.Brave,
                ProfileName = "Default",
                Extensions = new List<BrowserExtension> { new BrowserExtension { Id = "1" } }
            };

            var p2 = new BrowserProfile
            {
                BrowserType = BrowserType.Edge,
                ProfileName = "Default",
                Extensions = new List<BrowserExtension>()
            };

            Assert.Equal("Brave (Default) — 1 Eklenti", p1.DisplayText);
            Assert.Equal("Edge (Default) — Eklenti Yok", p2.DisplayText);
        }
    }
}
