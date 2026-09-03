using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace AegisPC.Performance.Hardware
{
    public class MotherboardInfo
    {
        public string Manufacturer { get; set; } = string.Empty;
        public string Product { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string Version { get; set; } = "1.0";
        public bool IsValid => !string.IsNullOrWhiteSpace(Manufacturer) && 
                               !Manufacturer.Equals("Bilinmiyor", StringComparison.OrdinalIgnoreCase) &&
                               !Manufacturer.Equals("Default string", StringComparison.OrdinalIgnoreCase) &&
                               !Manufacturer.Equals("To be filled by O.E.M.", StringComparison.OrdinalIgnoreCase);
    }

    public class GpuInfo
    {
        public string Name { get; set; } = "Standart Ekran Kartı";
        public long VramBytes { get; set; }
        public double VramGb => Math.Round((double)VramBytes / (1024 * 1024 * 1024), 1);
        public string DriverVersion { get; set; } = "N/A";
        public string VideoProcessor { get; set; } = "N/A";
        public string Resolution { get; set; } = "1920 x 1080";
        public int RefreshRateHz { get; set; } = 60;
    }

    public class CpuInfo
    {
        public string Name { get; set; } = "İşlemci";
        public int NumberOfCores { get; set; } = Environment.ProcessorCount / 2;
        public int NumberOfLogicalProcessors { get; set; } = Environment.ProcessorCount;
        public int MaxClockSpeedMhz { get; set; } = 3200;
        public int L3CacheSizeKb { get; set; }
        public string Socket { get; set; } = "N/A";
    }

    public class RamModuleInfo
    {
        public string DeviceLocator { get; set; } = "Slot 1";
        public long CapacityBytes { get; set; }
        public double CapacityGb => Math.Round((double)CapacityBytes / (1024 * 1024 * 1024), 1);
        public int SpeedMhz { get; set; }
        public string Manufacturer { get; set; } = "Bilinmiyor";
        public string PartNumber { get; set; } = "N/A";
        public string MemoryType { get; set; } = "DDR4 / DDR5";
    }

    public class DiskHardwareInfo
    {
        public string Model { get; set; } = "Depolama Birimi";
        public long SizeBytes { get; set; }
        public double SizeGb => Math.Round((double)SizeBytes / (1024 * 1024 * 1024), 1);
        public string InterfaceType { get; set; } = "NVMe / SATA";
        public string MediaType { get; set; } = "SSD";
        public string Status { get; set; } = "Sağlıklı (OK)";
    }

    public class CompleteHardwareProfile
    {
        public MotherboardInfo Motherboard { get; set; } = new();
        public List<GpuInfo> Gpus { get; set; } = new();
        public CpuInfo Cpu { get; set; } = new();
        public List<RamModuleInfo> RamModules { get; set; } = new();
        public List<DiskHardwareInfo> PhysicalDisks { get; set; } = new();
        public double TotalRamGb => RamModules.Sum(r => r.CapacityGb);
    }

    public interface IHardwareInfoService
    {
        Task<CompleteHardwareProfile> GetHardwareProfileAsync();
    }

    public class HardwareInfoService : IHardwareInfoService
    {
        private readonly ILogger<HardwareInfoService>? _logger;
        private CompleteHardwareProfile? _cachedProfile;
        private readonly object _lock = new();

        public HardwareInfoService(ILogger<HardwareInfoService>? logger = null)
        {
            _logger = logger;
        }

        public Task<CompleteHardwareProfile> GetHardwareProfileAsync()
        {
            return Task.Run(() =>
            {
                lock (_lock)
                {
                    if (_cachedProfile != null)
                    {
                        return _cachedProfile;
                    }

                    var profile = new CompleteHardwareProfile();

                    try
                    {
                        // 1. Motherboard (Win32_BaseBoard with Registry Fallback)
                        using (var searcher = new ManagementObjectSearcher("SELECT Manufacturer, Product, SerialNumber, Version FROM Win32_BaseBoard"))
                        {
                            foreach (ManagementObject obj in searcher.Get())
                            {
                                string mfg = obj["Manufacturer"]?.ToString()?.Trim() ?? "";
                                string prod = obj["Product"]?.ToString()?.Trim() ?? "";
                                string sn = obj["SerialNumber"]?.ToString()?.Trim() ?? "";
                                string ver = obj["Version"]?.ToString()?.Trim() ?? "1.0";

                                profile.Motherboard = new MotherboardInfo
                                {
                                    Manufacturer = mfg,
                                    Product = prod,
                                    SerialNumber = (sn.Equals("Default string", StringComparison.OrdinalIgnoreCase) || sn.Equals("To be filled by O.E.M.", StringComparison.OrdinalIgnoreCase)) ? "" : sn,
                                    Version = ver
                                };
                                break;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "WMI Motherboard query failed");
                    }

                    // Direct Registry fallback if WMI returned incomplete or generic data
                    if (!profile.Motherboard.IsValid)
                    {
                        try
                        {
                            using var biosKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
                            if (biosKey != null)
                            {
                                string mfg = biosKey.GetValue("BaseBoardManufacturer")?.ToString()?.Trim() ?? "";
                                string prod = biosKey.GetValue("BaseBoardProduct")?.ToString()?.Trim() ?? "";
                                string ver = biosKey.GetValue("BaseBoardVersion")?.ToString()?.Trim() ?? "1.0";

                                if (!string.IsNullOrWhiteSpace(mfg))
                                {
                                    profile.Motherboard.Manufacturer = mfg;
                                    profile.Motherboard.Product = prod;
                                    profile.Motherboard.Version = ver;
                                }
                            }
                        }
                        catch { }
                    }

                    try
                    {
                        // 2. CPU (Win32_Processor)
                        using (var searcher = new ManagementObjectSearcher("SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, L3CacheSize, SocketDesignation FROM Win32_Processor"))
                        {
                            foreach (ManagementObject obj in searcher.Get())
                            {
                                profile.Cpu = new CpuInfo
                                {
                                    Name = obj["Name"]?.ToString()?.Trim() ?? "Intel / AMD İşlemci",
                                    NumberOfCores = Convert.ToInt32(obj["NumberOfCores"] ?? (Environment.ProcessorCount / 2)),
                                    NumberOfLogicalProcessors = Convert.ToInt32(obj["NumberOfLogicalProcessors"] ?? Environment.ProcessorCount),
                                    MaxClockSpeedMhz = Convert.ToInt32(obj["MaxClockSpeed"] ?? 3200),
                                    L3CacheSizeKb = Convert.ToInt32(obj["L3CacheSize"] ?? 0),
                                    Socket = obj["SocketDesignation"]?.ToString()?.Trim() ?? "N/A"
                                };
                                break;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "WMI CPU query failed");
                    }

                    try
                    {
                        // 3. GPU (Win32_VideoController)
                        using (var searcher = new ManagementObjectSearcher("SELECT Name, AdapterRAM, DriverVersion, VideoProcessor, VideoModeDescription, CurrentRefreshRate FROM Win32_VideoController"))
                        {
                            foreach (ManagementObject obj in searcher.Get())
                            {
                                string name = obj["Name"]?.ToString()?.Trim() ?? "";
                                if (string.IsNullOrEmpty(name) || name.Contains("Basic Display", StringComparison.OrdinalIgnoreCase)) continue;

                                long vram = 0;
                                if (obj["AdapterRAM"] != null)
                                {
                                    long.TryParse(obj["AdapterRAM"]?.ToString(), out vram);
                                }

                                profile.Gpus.Add(new GpuInfo
                                {
                                    Name = name,
                                    VramBytes = vram,
                                    DriverVersion = obj["DriverVersion"]?.ToString()?.Trim() ?? "N/A",
                                    VideoProcessor = obj["VideoProcessor"]?.ToString()?.Trim() ?? name,
                                    Resolution = obj["VideoModeDescription"]?.ToString()?.Trim() ?? "1920 x 1080",
                                    RefreshRateHz = Convert.ToInt32(obj["CurrentRefreshRate"] ?? 60)
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "WMI GPU query failed");
                    }

                    try
                    {
                        // 4. RAM (Win32_PhysicalMemory)
                        using (var searcher = new ManagementObjectSearcher("SELECT Capacity, Speed, Manufacturer, PartNumber, DeviceLocator, MemoryType FROM Win32_PhysicalMemory"))
                        {
                            foreach (ManagementObject obj in searcher.Get())
                            {
                                long capacity = 0;
                                if (obj["Capacity"] != null)
                                {
                                    long.TryParse(obj["Capacity"]?.ToString(), out capacity);
                                }

                                profile.RamModules.Add(new RamModuleInfo
                                {
                                    DeviceLocator = obj["DeviceLocator"]?.ToString()?.Trim() ?? "DIMM",
                                    CapacityBytes = capacity,
                                    SpeedMhz = Convert.ToInt32(obj["Speed"] ?? 3200),
                                    Manufacturer = obj["Manufacturer"]?.ToString()?.Trim() ?? "Crucial/Kingston/Corsair",
                                    PartNumber = obj["PartNumber"]?.ToString()?.Trim() ?? "N/A",
                                    MemoryType = "DDR4 / DDR5"
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "WMI RAM query failed");
                    }

                    try
                    {
                        // 5. Physical Disks (Win32_DiskDrive)
                        using (var searcher = new ManagementObjectSearcher("SELECT Model, Size, InterfaceType, MediaType, Status FROM Win32_DiskDrive"))
                        {
                            foreach (ManagementObject obj in searcher.Get())
                            {
                                long size = 0;
                                if (obj["Size"] != null)
                                {
                                    long.TryParse(obj["Size"]?.ToString(), out size);
                                }

                                string model = obj["Model"]?.ToString()?.Trim() ?? "Disk";
                                string interfaceType = obj["InterfaceType"]?.ToString()?.Trim() ?? "NVMe / SATA";
                                string mediaType = obj["MediaType"]?.ToString()?.Trim() ?? (model.Contains("NVMe", StringComparison.OrdinalIgnoreCase) || model.Contains("SSD", StringComparison.OrdinalIgnoreCase) ? "SSD" : "HDD");

                                profile.PhysicalDisks.Add(new DiskHardwareInfo
                                {
                                    Model = model,
                                    SizeBytes = size,
                                    InterfaceType = interfaceType,
                                    MediaType = mediaType,
                                    Status = obj["Status"]?.ToString()?.Trim() ?? "Sağlıklı (OK)"
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "WMI Disk query failed");
                    }

                    _cachedProfile = profile;
                    return profile;
                }
            });
        }
    }
}
