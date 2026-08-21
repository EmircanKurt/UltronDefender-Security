using System.Collections.Generic;

namespace AegisPC.Core.Constants;

public static class CriticalProcesses
{
    public static readonly HashSet<string> List = new(System.StringComparer.OrdinalIgnoreCase)
    {
        "System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
        "spoolsv.exe", "taskhostw.exe", "sihost.exe"
    };

    public static bool IsCriticalProcess(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        return List.Contains(name) || List.Contains(name + ".exe");
    }
}
