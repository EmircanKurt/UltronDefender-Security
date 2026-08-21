using System.Text.Json;

namespace AegisPC.ElevatedHelper;

/// <summary>
/// Elevated helper process for operations requiring administrator privileges.
/// This process is short-lived: it executes a single command and exits.
/// Communication with the main app is via stdout JSON.
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
        {
            WriteResult(false, "Komut belirtilmedi. Bu uygulama doğrudan çalıştırılmak için tasarlanmamıştır.");
            return 1;
        }

        var command = args[0].ToLowerInvariant();
        var commandArgs = args.Skip(1).ToArray();

        try
        {
            return command switch
            {
                "--disable-startup" => HandleDisableStartup(commandArgs),
                "--enable-startup" => HandleEnableStartup(commandArgs),
                "--terminate-process" => await HandleTerminateProcess(commandArgs),
                "--help" => HandleHelp(),
                _ => HandleUnknownCommand(command)
            };
        }
        catch (UnauthorizedAccessException ex)
        {
            WriteResult(false, $"Erişim reddedildi: {ex.Message}");
            return 2;
        }
        catch (Exception ex)
        {
            WriteResult(false, $"İşlem başarısız: {ex.Message}");
            return 3;
        }
    }

    private static int HandleDisableStartup(string[] args)
    {
        if (args.Length < 2)
        {
            WriteResult(false, "Kullanım: --disable-startup <registryPath> <valueName>");
            return 1;
        }

        var registryPath = args[0];
        var valueName = args[1];

        // Validate the registry path is a known startup location
        if (!IsValidStartupRegistryPath(registryPath))
        {
            WriteResult(false, "Geçersiz registry yolu. Yalnızca bilinen başlangıç konumları desteklenir.");
            return 1;
        }

        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(registryPath, writable: true);
        if (key == null)
        {
            WriteResult(false, $"Registry anahtarı bulunamadı: HKLM\\{registryPath}");
            return 1;
        }

        var currentValue = key.GetValue(valueName);
        if (currentValue == null)
        {
            WriteResult(false, $"Registry değeri bulunamadı: {valueName}");
            return 1;
        }

        // Store backup value as JSON
        var backup = JsonSerializer.Serialize(new
        {
            Path = $"HKLM\\{registryPath}",
            Name = valueName,
            Value = currentValue.ToString(),
            Type = key.GetValueKind(valueName).ToString(),
            DisabledAt = DateTime.UtcNow.ToString("o")
        });

        key.DeleteValue(valueName);
        WriteResult(true, "Başlangıç girdisi devre dışı bırakıldı.", backup);
        return 0;
    }

    private static int HandleEnableStartup(string[] args)
    {
        if (args.Length < 3)
        {
            WriteResult(false, "Kullanım: --enable-startup <registryPath> <valueName> <value>");
            return 1;
        }

        var registryPath = args[0];
        var valueName = args[1];
        var value = args[2];

        if (!IsValidStartupRegistryPath(registryPath))
        {
            WriteResult(false, "Geçersiz registry yolu. Yalnızca bilinen başlangıç konumları desteklenir.");
            return 1;
        }

        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(registryPath, writable: true);
        if (key == null)
        {
            WriteResult(false, $"Registry anahtarı bulunamadı: HKLM\\{registryPath}");
            return 1;
        }

        key.SetValue(valueName, value, Microsoft.Win32.RegistryValueKind.String);
        WriteResult(true, "Başlangıç girdisi yeniden etkinleştirildi.");
        return 0;
    }

    private static async Task<int> HandleTerminateProcess(string[] args)
    {
        if (args.Length == 0 || !int.TryParse(args[0], out var pid))
        {
            WriteResult(false, "Kullanım: --terminate-process <PID>");
            return 1;
        }

        try
        {
            var process = System.Diagnostics.Process.GetProcessById(pid);
            var processName = process.ProcessName;

            // Safety check - never terminate critical system processes
            var criticalProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "System", "smss", "csrss", "wininit", "winlogon", "services",
                "lsass", "svchost", "dwm", "fontdrvhost", "lsaiso", "SecurityHealthService"
            };

            if (criticalProcesses.Contains(processName))
            {
                WriteResult(false, $"'{processName}' kritik bir sistem sürecidir ve sonlandırılamaz.");
                return 1;
            }

            process.Kill();
            await process.WaitForExitAsync();
            WriteResult(true, $"'{processName}' (PID: {pid}) sonlandırıldı.");
            return 0;
        }
        catch (ArgumentException)
        {
            WriteResult(false, $"PID {pid} ile eşleşen süreç bulunamadı.");
            return 1;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            WriteResult(false, $"Süreç sonlandırılamadı. Windows erişimi reddetti: {ex.Message}");
            return 2;
        }
    }

    private static int HandleHelp()
    {
        Console.WriteLine("AegisPC Elevated Helper");
        Console.WriteLine("Kullanım:");
        Console.WriteLine("  --disable-startup <registryPath> <valueName>");
        Console.WriteLine("  --enable-startup <registryPath> <valueName> <value>");
        Console.WriteLine("  --terminate-process <PID>");
        return 0;
    }

    private static int HandleUnknownCommand(string command)
    {
        WriteResult(false, $"Bilinmeyen komut: {command}");
        return 1;
    }

    private static bool IsValidStartupRegistryPath(string path)
    {
        var validPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        };

        return validPaths.Any(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase));
    }

    private static void WriteResult(bool success, string message, string? data = null)
    {
        var result = new
        {
            Success = success,
            Message = message,
            Data = data,
            Timestamp = DateTime.UtcNow.ToString("o")
        };
        Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
