using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Performance.Process
{
    public class ProcessMonitorService : IProcessMonitor
    {
        private readonly ILogger<ProcessMonitorService>? _logger;
        private readonly ConcurrentDictionary<int, (TimeSpan totalCpu, DateTime sampleTime)> _previousCpuTimes = new();
        private List<ProcessInfo> _cachedProcesses = new();
        private readonly object _lock = new();
        private DateTime _lastRefreshTime = DateTime.MinValue;

        #region Native Win32 ToolHelp API for Parent Process ID
        private const uint TH32CS_SNAPPROCESS = 0x00000002;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static Dictionary<int, int> GetProcessParentMap()
        {
            var parentMap = new Dictionary<int, int>();
            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            if (snapshot == INVALID_HANDLE_VALUE) return parentMap;

            try
            {
                var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
                if (Process32First(snapshot, ref entry))
                {
                    do
                    {
                        parentMap[(int)entry.th32ProcessID] = (int)entry.th32ParentProcessID;
                    } while (Process32Next(snapshot, ref entry));
                }
            }
            catch { }
            finally
            {
                CloseHandle(snapshot);
            }

            return parentMap;
        }
        #endregion

        public ProcessMonitorService(ILogger<ProcessMonitorService>? logger = null)
        {
            _logger = logger;
        }

        public async Task<List<ProcessInfo>> GetAllProcessesAsync()
        {
            if ((DateTime.UtcNow - _lastRefreshTime).TotalSeconds > 1.5 || _cachedProcesses.Count == 0)
            {
                await RefreshAsync();
            }

            lock (_lock)
            {
                return _cachedProcesses.ToList();
            }
        }

        public Task<ProcessInfo?> GetProcessByPidAsync(int pid)
        {
            lock (_lock)
            {
                var process = _cachedProcesses.FirstOrDefault(p => p.PID == pid);
                return Task.FromResult(process);
            }
        }

        public async Task<List<ProcessTreeNode>> GetProcessTreeAsync()
        {
            var processes = await GetAllProcessesAsync();
            return await Task.Run(() => ProcessTreeBuilder.BuildTree(processes));
        }

        public async Task RefreshAsync()
        {
            var updatedList = await Task.Run(async () =>
            {
                // First pass if empty
                if (_previousCpuTimes.IsEmpty)
                {
                    SampleCpuTimes();
                    await Task.Delay(120);
                }

                return FetchProcessesFast();
            });

            lock (_lock)
            {
                _cachedProcesses = updatedList;
                _lastRefreshTime = DateTime.UtcNow;
            }
        }

        private void SampleCpuTimes()
        {
            var now = DateTime.UtcNow;
            foreach (var proc in global::System.Diagnostics.Process.GetProcesses())
            {
                try
                {
                    _previousCpuTimes[proc.Id] = (proc.TotalProcessorTime, now);
                }
                catch { }
                finally
                {
                    proc.Dispose();
                }
            }
        }

        private List<ProcessInfo> FetchProcessesFast()
        {
            var systemProcesses = global::System.Diagnostics.Process.GetProcesses();
            var parentMap = GetProcessParentMap();
            var list = new List<ProcessInfo>(systemProcesses.Length);
            var now = DateTime.UtcNow;
            int processorCount = Math.Max(1, Environment.ProcessorCount);

            foreach (var proc in systemProcesses)
            {
                try
                {
                    int pid = proc.Id;
                    string name = proc.ProcessName;
                    long workingSet = 0;
                    DateTime startTime = now;
                    int sessionId = 0;
                    string execPath = string.Empty;
                    double cpuPercent = 0.0;
                    int parentPid = parentMap.TryGetValue(pid, out var ppid) ? ppid : 0;

                    try { workingSet = proc.WorkingSet64; } catch { }
                    try { sessionId = proc.SessionId; } catch { }
                    try { startTime = proc.StartTime; } catch { }
                    try { execPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                    // CPU usage delta
                    try
                    {
                        var totalProcessorTime = proc.TotalProcessorTime;
                        if (_previousCpuTimes.TryGetValue(pid, out var prev))
                        {
                            var deltaCpu = (totalProcessorTime - prev.totalCpu).TotalMilliseconds;
                            var deltaTime = (now - prev.sampleTime).TotalMilliseconds;
                            if (deltaTime > 0)
                            {
                                cpuPercent = (deltaCpu / (deltaTime * processorCount)) * 100.0;
                                cpuPercent = Math.Clamp(Math.Round(cpuPercent, 1), 0.0, 100.0);
                            }
                        }
                        _previousCpuTimes[pid] = (totalProcessorTime, now);
                    }
                    catch { }

                    double gpuPercent = 0.0; // TODO: Real GPU monitoring via PDH/NVML

                    // Heuristic Risk evaluation based on process name and path
                    var riskLevel = EvaluateProcessRisk(name, execPath);

                    var info = new ProcessInfo
                    {
                        PID = pid,
                        Name = name,
                        MemoryBytes = workingSet,
                        StartTime = startTime,
                        SessionId = sessionId,
                        ExecutablePath = execPath,
                        CpuPercent = cpuPercent,
                        GpuPercent = gpuPercent,
                        ParentPid = parentPid,
                        RiskLevel = riskLevel
                    };

                    list.Add(info);
                }
                catch { }
                finally
                {
                    proc.Dispose();
                }
            }

            // Cleanup stale PIDs
            var currentPids = new HashSet<int>(list.Select(p => p.PID));
            foreach (var key in _previousCpuTimes.Keys)
            {
                if (!currentPids.Contains(key))
                {
                    _previousCpuTimes.TryRemove(key, out _);
                }
            }

            return list;
        }

        private static RiskLevel EvaluateProcessRisk(string name, string path)
        {
            if (string.IsNullOrEmpty(path)) return RiskLevel.Clean;

            var lowerPath = path.ToLowerInvariant();
            var lowerName = name.ToLowerInvariant();

            // Check for processes running from Temp or AppData without signatures
            if (lowerPath.Contains("\\appdata\\local\\temp\\") || lowerPath.Contains("\\windows\\temp\\"))
            {
                return RiskLevel.Suspicious;
            }

            // Suspicious LOLBins running outside System32
            if ((lowerName == "powershell" || lowerName == "cmd" || lowerName == "certutil" || lowerName == "mshta" || lowerName == "vbc" || lowerName == "csc")
                && !lowerPath.Contains("\\windows\\system32\\") && !lowerPath.Contains("\\windows\\syswow64\\") && !lowerPath.Contains("\\windows\\microsoft.net\\"))
            {
                return RiskLevel.Suspicious;
            }

            return RiskLevel.Clean;
        }
    }
}
