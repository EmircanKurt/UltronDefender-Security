using System;
using System.Collections.ObjectModel;
using System.Windows;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AegisPC.App.ViewModels
{
    public partial class RealTimeMonitorViewModel : ObservableObject
    {
        private readonly IPerformanceMonitor? _performanceMonitor;

        [ObservableProperty]
        private string pageTitle = "Gerçek Zamanlı Sistem İzleme";

        [ObservableProperty]
        private double currentCpu;

        [ObservableProperty]
        private double currentRamPercent;

        [ObservableProperty]
        private long currentRamUsedBytes;

        [ObservableProperty]
        private long currentRamTotalBytes;

        [ObservableProperty]
        private double currentDiskUsage;

        [ObservableProperty]
        private double currentNetworkDownMBps;

        [ObservableProperty]
        private double currentNetworkUpMBps;

        [ObservableProperty]
        private int activeProcesses;

        [ObservableProperty]
        private ObservableCollection<PerformanceSample> recentSamples = new();

        public RealTimeMonitorViewModel(IPerformanceMonitor? performanceMonitor = null)
        {
            _performanceMonitor = performanceMonitor;

            if (_performanceMonitor != null)
            {
                _performanceMonitor.OnSampleCollected += OnSampleReceived;
            }
        }

        private void OnSampleReceived(object? sender, PerformanceSample sample)
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                CurrentCpu = sample.CpuPercent;
                CurrentRamTotalBytes = sample.MemoryTotalBytes;
                CurrentRamUsedBytes = sample.MemoryUsedBytes;
                CurrentRamPercent = sample.MemoryTotalBytes > 0 
                    ? Math.Round(((double)sample.MemoryUsedBytes / sample.MemoryTotalBytes) * 100.0, 1) 
                    : 0;
                CurrentDiskUsage = sample.DiskUsagePercent;
                CurrentNetworkDownMBps = Math.Round(sample.NetworkDownBps / (1024.0 * 1024.0), 2);
                CurrentNetworkUpMBps = Math.Round(sample.NetworkUpBps / (1024.0 * 1024.0), 2);
                ActiveProcesses = sample.ActiveProcesses;

                RecentSamples.Insert(0, sample);
                while (RecentSamples.Count > 30)
                {
                    RecentSamples.RemoveAt(RecentSamples.Count - 1);
                }
            });
        }
    }
}
