using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using AegisPC.Contracts.Kernel;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Kernel
{
    /// <summary>
    /// Çekirdek (Kernel Minifilter) dosya telemetri olaylarını (Pre/Post Create, Write, Cleanup)
    /// yüksek performansla alan, NT Aygıt yollarını DOS yollarına dönüştüren telemetri motoru.
    /// </summary>
    public class KernelMinifilterTelemetryEngine : IKernelTelemetryEngine
    {
        private readonly ILogger<KernelMinifilterTelemetryEngine>? _logger;
        private readonly ConcurrentDictionary<string, string> _deviceToDosMap = new(StringComparer.OrdinalIgnoreCase);

        public event Action<KernelFileTelemetryEvent>? OnTelemetryReceived;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint QueryDosDevice(string? lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);

        public KernelMinifilterTelemetryEngine(ILogger<KernelMinifilterTelemetryEngine>? logger = null)
        {
            _logger = logger;
            RefreshDeviceMap();
        }

        public void RefreshDeviceMap()
        {
            try
            {
                var sb = new StringBuilder(1024);
                foreach (var drive in DriveInfo.GetDrives())
                {
                    var driveLetter = drive.Name.TrimEnd('\\');
                    uint result = QueryDosDevice(driveLetter, sb, (uint)sb.Capacity);
                    if (result > 0)
                    {
                        var ntPath = sb.ToString();
                        _deviceToDosMap[ntPath] = driveLetter;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Failed to refresh DOS device mapping.");
            }
        }

        public string ResolveNtDeviceToDosPath(string ntPath)
        {
            if (string.IsNullOrWhiteSpace(ntPath)) return string.Empty;

            foreach (var kvp in _deviceToDosMap)
            {
                if (ntPath.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value + ntPath[kvp.Key.Length..];
                }
            }

            return ntPath;
        }

        public void IngestKernelEvent(KernelFileTelemetryEvent rawEvent)
        {
            if (rawEvent == null) return;

            // Paging I/O (Bellek Sayfalama) gürültü filtrelemesi
            if (rawEvent.IsPagingIo) return;

            // NT Device -> Canonical DOS Path dönüşümü
            if (string.IsNullOrEmpty(rawEvent.CanonicalDosPath) && !string.IsNullOrEmpty(rawEvent.NtDevicePath))
            {
                rawEvent.CanonicalDosPath = ResolveNtDeviceToDosPath(rawEvent.NtDevicePath);
            }

            OnTelemetryReceived?.Invoke(rawEvent);
        }
    }
}
