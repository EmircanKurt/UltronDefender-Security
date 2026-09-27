using System;
using System.Threading;
using AegisPC.App.ViewModels;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class ScanWindowIdleAndProgressionTests
    {
        [Fact]
        public void ScanViewModel_IdleState_ReportsCorrectFlagsAndButtonText()
        {
            Exception? threadEx = null;
            var staThread = new Thread(() =>
            {
                try
                {
                    var hashService = new HashService();
                    var sigVerifier = new SignatureVerifier();
                    var riskScoring = new RiskScoringEngine();
                    var allowlist = new AllowlistService(hashService);
                    var findingService = new SecurityFindingService();
                    var fileScanner = new FileScannerService(hashService, sigVerifier, riskScoring, allowlist, findingService);
                    var coordinator = new ScanCoordinatorService(fileScanner, findingService);

                    var vm = new ScanViewModel(coordinator, findingService);

                    // Başlangıçta boşta durumunda olmalı
                    Assert.False(vm.IsScanning);
                    Assert.False(vm.IsScanFinishedView);
                    Assert.True(vm.IsIdleView);
                    Assert.Equal("Tarayıcı Penceresini Aç", vm.OpenScanWindowButtonText);

                    // ResetScanState çağrıldığında tarama başlıyor durumuna geçmeli
                    vm.ResetScanState(ScanType.Quick);
                    Assert.True(vm.IsScanning);
                    Assert.False(vm.IsIdleView);
                    Assert.Equal("Aktif Taramayı Görüntüle", vm.OpenScanWindowButtonText);

                    // CloseResults çağrıldığında tekrar boşta durumuna dönmeli
                    vm.CloseResults();
                    Assert.False(vm.IsScanning);
                    Assert.False(vm.IsScanFinishedView);
                    Assert.True(vm.IsIdleView);
                    Assert.Equal("Tarayıcı Penceresini Aç", vm.OpenScanWindowButtonText);
                }
                catch (Exception ex)
                {
                    threadEx = ex;
                }
            });

            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();
            staThread.Join();

            if (threadEx != null) throw threadEx;
        }

        [Fact]
        public void ScanViewModel_ChecklistProgression_TransitionsStepsDynamically()
        {
            Exception? threadEx = null;
            var staThread = new Thread(() =>
            {
                try
                {
                    var hashService = new HashService();
                    var sigVerifier = new SignatureVerifier();
                    var riskScoring = new RiskScoringEngine();
                    var allowlist = new AllowlistService(hashService);
                    var findingService = new SecurityFindingService();
                    var fileScanner = new FileScannerService(hashService, sigVerifier, riskScoring, allowlist, findingService);
                    var coordinator = new ScanCoordinatorService(fileScanner, findingService);

                    var vm = new ScanViewModel(coordinator, findingService);
                    vm.ResetScanState(ScanType.Quick);

                    // %0 (Başlangıç): Adım 1 aktif olmalı, Adım 2-5 henüz başlamamış (pending) olmalı
                    Assert.False(vm.IsStep1Done);
                    Assert.True(vm.IsStep1Active);
                    Assert.False(vm.IsStep2Done);
                    Assert.True(vm.IsStep2Pending);
                    Assert.False(vm.IsStep5Done);

                    // %10: Adım 1 bitti, Adım 2 aktif
                    vm.ProgressPercentage = 10;
                    Assert.True(vm.IsStep1Done);
                    Assert.False(vm.IsStep1Active);
                    Assert.False(vm.IsStep2Done);
                    Assert.True(vm.IsStep2Active);
                    Assert.True(vm.IsStep3Pending);

                    // %25: Adım 1 ve 2 bitti, Adım 3 aktif
                    vm.ProgressPercentage = 25;
                    Assert.True(vm.IsStep1Done);
                    Assert.True(vm.IsStep2Done);
                    Assert.False(vm.IsStep3Done);
                    Assert.True(vm.IsStep3Active);
                    Assert.True(vm.IsStep4Pending);

                    // %40: Adım 1, 2, 3 bitti, Adım 4 aktif
                    vm.ProgressPercentage = 40;
                    Assert.True(vm.IsStep3Done);
                    Assert.False(vm.IsStep4Done);
                    Assert.True(vm.IsStep4Active);
                    Assert.True(vm.IsStep5Pending);

                    // %60: Adım 1, 2, 3, 4 bitti, Adım 5 (dosya sistemi taraması) aktif
                    vm.ProgressPercentage = 60;
                    Assert.True(vm.IsStep4Done);
                    Assert.False(vm.IsStep5Done);
                    Assert.True(vm.IsStep5Active);

                    // %100: Tüm adımlar tamamlandı
                    vm.ProgressPercentage = 100;
                    Assert.True(vm.IsStep5Done);
                    Assert.False(vm.IsStep5Active);
                }
                catch (Exception ex)
                {
                    threadEx = ex;
                }
            });

            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();
            staThread.Join();

            if (threadEx != null) throw threadEx;
        }

        [Fact]
        public void ScanViewModel_OpenActiveScanWindowAsync_WhenIdle_SetsScanningFlag()
        {
            Exception? threadEx = null;
            var staThread = new Thread(() =>
            {
                try
                {
                    var hashService = new HashService();
                    var sigVerifier = new SignatureVerifier();
                    var riskScoring = new RiskScoringEngine();
                    var allowlist = new AllowlistService(hashService);
                    var findingService = new SecurityFindingService();
                    var fileScanner = new FileScannerService(hashService, sigVerifier, riskScoring, allowlist, findingService);
                    var coordinator = new ScanCoordinatorService(fileScanner, findingService);

                    var vm = new ScanViewModel(coordinator, findingService);

                    Assert.False(vm.IsScanning);
                    Assert.True(vm.IsIdleView);

                    // OpenActiveScanWindowCommand çalıştırıldığında IsScanning true olmalı
                    var task = vm.OpenActiveScanWindowCommand.ExecuteAsync(null);
                    Assert.True(vm.IsScanning);
                    Assert.False(vm.IsIdleView);

                    // İptal edip temizle
                    vm.CancelScanCommand.Execute(null);
                }
                catch (Exception ex)
                {
                    threadEx = ex;
                }
            });

            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();
            staThread.Join();

            if (threadEx != null) throw threadEx;
        }
    }
}
