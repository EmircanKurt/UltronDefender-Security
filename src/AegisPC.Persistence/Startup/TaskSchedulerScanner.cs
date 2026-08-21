using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Persistence.Startup
{
    public static class TaskSchedulerScanner
    {
        public static List<StartupItem> ScanLogonTasks()
        {
            var items = new List<StartupItem>();

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = "/query /fo CSV /nh",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return items;

                using var reader = process.StandardOutput;
                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    // Parse CSV line: "TaskName","Next Run Time","Status"
                    var parts = line.Split("\",\"");
                    if (parts.Length >= 1)
                    {
                        var taskName = parts[0].Trim('"');
                        // Skip Microsoft internal system tasks for cleaner persistence view
                        if (taskName.StartsWith("\\Microsoft\\Windows\\", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        items.Add(new StartupItem
                        {
                            Name = Path.GetFileName(taskName),
                            FilePath = taskName,
                            Source = "Zamanlanmış Görev (Task Scheduler)",
                            IsEnabled = parts.Length > 2 && !parts[2].Contains("Disabled", StringComparison.OrdinalIgnoreCase),
                            RiskLevel = RiskLevel.Clean,
                            ImpactLevel = ImpactLevel.Low
                        });
                    }
                }

                process.WaitForExit(3000);
            }
            catch { }

            return items;
        }
    }
}
