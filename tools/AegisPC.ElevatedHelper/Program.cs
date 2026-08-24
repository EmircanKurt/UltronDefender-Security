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
                "--set-dns" => HandleSetDns(commandArgs),
                "--flush-dns" => HandleFlushDns(),
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

    private static int HandleSetDns(string[] args)
    {
        if (args.Length < 2)
        {
            WriteResult(false, "Kullanım: --set-dns <adapterName> <dhcp|ip1,ip2>");
            return 1;
        }

        var adapterName = args[0];
        var dnsConfig = args[1];

        try
        {
            bool success = false;
            string detail = "";

            if (dnsConfig.Equals("dhcp", StringComparison.OrdinalIgnoreCase) || dnsConfig.Equals("automatic", StringComparison.OrdinalIgnoreCase))
            {
                var r = RunNetsh($"interface ipv4 set dns name=\"{adapterName}\" source=dhcp");
                success = r.ExitCode == 0;
                detail = r.Output + " " + r.Error;

                // Also try PowerShell as secondary fallback if netsh exit code != 0
                if (!success)
                {
                    var psResult = RunPowerShell($"Set-DnsClientServerAddress -InterfaceAlias '{adapterName}' -ResetServerAddresses");
                    if (psResult.ExitCode == 0)
                    {
                        success = true;
                    }
                }
            }
            else
            {
                var ips = dnsConfig.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (ips.Length > 0)
                {
                    var r1 = RunNetsh($"interface ipv4 set dns name=\"{adapterName}\" static {ips[0].Trim()} primary");
                    if (r1.ExitCode == 0)
                    {
                        success = true;
                        if (ips.Length > 1)
                        {
                            var r2 = RunNetsh($"interface ipv4 add dns name=\"{adapterName}\" {ips[1].Trim()} index=2");
                        }
                    }
                    else
                    {
                        detail = r1.Output + " " + r1.Error;
                        // PowerShell fallback
                        var ipsJoined = string.Join("','", ips.Select(x => x.Trim()));
                        var psResult = RunPowerShell($"Set-DnsClientServerAddress -InterfaceAlias '{adapterName}' -ServerAddresses ('{ipsJoined}')");
                        if (psResult.ExitCode == 0)
                        {
                            success = true;
                        }
                    }
                }
            }

            // Flush DNS resolver cache
            RunProcess("ipconfig.exe", "/flushdns");

            if (success)
            {
                WriteResult(true, $"'{adapterName}' için DNS yapılandırması başarıyla uygulandı.");
                return 0;
            }
            else
            {
                WriteResult(false, $"DNS güncellenemedi: {detail.Trim()}");
                return 1;
            }
        }
        catch (Exception ex)
        {
            WriteResult(false, $"Hata: {ex.Message}");
            return 2;
        }
    }

    private static int HandleFlushDns()
    {
        try
        {
            var res = RunProcess("ipconfig.exe", "/flushdns");
            WriteResult(res.ExitCode == 0, res.ExitCode == 0 ? "DNS önbelleği temizlendi." : res.Error);
            return res.ExitCode;
        }
        catch (Exception ex)
        {
            WriteResult(false, $"DNS temizleme hatası: {ex.Message}");
            return 1;
        }
    }

    private static (int ExitCode, string Output, string Error) RunNetsh(string args)
    {
        return RunProcess("netsh.exe", args);
    }

    private static (int ExitCode, string Output, string Error) RunPowerShell(string script)
    {
        return RunProcess("powershell.exe", $"-NoProfile -NonInteractive -Command \"{script}\"");
    }

    private static (int ExitCode, string Output, string Error) RunProcess(string fileName, string args)
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = fileName,
            Arguments = args,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var proc = System.Diagnostics.Process.Start(psi);
        if (proc == null) return (-1, "", "Process başlatılamadı.");
        var output = proc.StandardOutput.ReadToEnd();
        var error = proc.StandardError.ReadToEnd();
        proc.WaitForExit(6000);
        return (proc.ExitCode, output, error);
    }

    private static int HandleHelp()
    {
        Console.WriteLine("AegisPC Elevated Helper");
        Console.WriteLine("Kullanım:");
        Console.WriteLine("  --disable-startup <registryPath> <valueName>");
        Console.WriteLine("  --enable-startup <registryPath> <valueName> <value>");
        Console.WriteLine("  --terminate-process <PID>");
        Console.WriteLine("  --set-dns <adapterName> <dhcp|ip1,ip2>");
        Console.WriteLine("  --flush-dns");
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
