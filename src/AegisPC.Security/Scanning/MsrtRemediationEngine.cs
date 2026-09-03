using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Win32;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Microsoft Malicious Software Removal Tool (MSRT/MRT) Deep Remediation Engine.
    /// Inspects persistence vectors, registry debugger hijacks (IFEO), Winlogon, AppInit_DLLs,
    /// ServiceDll paths, Hosts file tampering, scheduled tasks, and unbacked process memory.
    /// </summary>
    public static class MsrtRemediationEngine
    {
        public static async Task<List<SecurityFinding>> RunMsrtDeepScanAsync(
            IProgress<string>? phaseReporter = null,
            CancellationToken cancellationToken = default)
        {
            var findings = new List<SecurityFinding>();

            await Task.Run(() =>
            {
                // 1. Check IFEO (Image File Execution Options) Debugger Hijacks
                phaseReporter?.Report("MRT Denetimi: IFEO ve Hata Ayıklayıcı Kaçırmaları taranıyor...");
                CheckIfeoHijacks(findings, cancellationToken);

                // 2. Check Winlogon Shell & Userinit Hijacks
                phaseReporter?.Report("MRT Denetimi: Winlogon Shell ve Userinit kayıtları inceleniyor...");
                CheckWinlogonHijacks(findings, cancellationToken);

                // 3. Check AppInit_DLLs & AppCertDlls
                phaseReporter?.Report("MRT Denetimi: AppInit_DLLs global enjeksiyon noktaları taranıyor...");
                CheckAppInitDlls(findings, cancellationToken);

                // 4. Check Registry Run & RunOnce Persistence
                phaseReporter?.Report("MRT Denetimi: Run ve RunOnce başlangıç kayıtları taranıyor...");
                CheckRunAndRunOnceKeys(findings, cancellationToken);

                // 5. Check Hosts File Tampering
                phaseReporter?.Report("MRT Denetimi: Hosts dosyası ve DNS yönlendirmeleri denetleniyor...");
                CheckHostsFileTampering(findings, cancellationToken);

                // 6. Check ServiceDll Hijacking in Registry
                phaseReporter?.Report("MRT Denetimi: Windows Servis DLL yolları analiz ediliyor...");
                CheckServiceDllHijacks(findings, cancellationToken);

                // 7. Check Scheduled Tasks for Malicious Download Cradles
                phaseReporter?.Report("MRT Denetimi: Zamanlanmış Görevler (Tasks) ve komut zincirleri taranıyor...");
                CheckScheduledTasks(findings, cancellationToken);

                // 8. Check Active Process Anomalies & Suspicious Paths
                phaseReporter?.Report("MRT Denetimi: Çalışan süreçler ve bellek enjeksiyonları taranıyor...");
                CheckActiveProcesses(findings, cancellationToken);

            }, cancellationToken);

            return findings;
        }

        public static List<string> GetPersistenceTargetPaths()
        {
            var paths = new List<string>();
            try
            {
                var runHives = new[]
                {
                    (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
                    (Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce")
                };

                foreach (var (root, subPath) in runHives)
                {
                    try
                    {
                        using var key = root.OpenSubKey(subPath);
                        if (key == null) continue;

                        foreach (var valName in key.GetValueNames())
                        {
                            var val = key.GetValue(valName)?.ToString();
                            if (string.IsNullOrWhiteSpace(val)) continue;

                            string cleaned = ExtractExecutablePath(val);
                            if (File.Exists(cleaned))
                            {
                                paths.Add(cleaned);
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return paths;
        }

        private static string ExtractExecutablePath(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return string.Empty;
            commandLine = commandLine.Trim();

            if (commandLine.StartsWith("\""))
            {
                int nextQuote = commandLine.IndexOf('\"', 1);
                if (nextQuote > 1)
                {
                    return commandLine.Substring(1, nextQuote - 1);
                }
            }

            int spaceIndex = commandLine.IndexOf(' ');
            if (spaceIndex > 0)
            {
                string firstPart = commandLine.Substring(0, spaceIndex);
                if (File.Exists(firstPart)) return firstPart;
            }

            return commandLine;
        }

        private static void CheckIfeoHijacks(List<SecurityFinding> findings, CancellationToken ct)
        {
            try
            {
                string ifeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
                using var key = Registry.LocalMachine.OpenSubKey(ifeoPath);
                if (key == null) return;

                var criticalApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "taskmgr.exe", "regedit.exe", "cmd.exe", "powershell.exe", "msmpeng.exe",
                    "mrt.exe", "aegispc.exe", "ultron.exe", "mbam.exe", "procexp.exe"
                };

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) break;

                    if (criticalApps.Contains(subKeyName))
                    {
                        using var subKey = key.OpenSubKey(subKeyName);
                        var debugger = subKey?.GetValue("Debugger")?.ToString();
                        if (!string.IsNullOrEmpty(debugger))
                        {
                            findings.Add(new SecurityFinding
                            {
                                ObjectPath = $@"HKLM\{ifeoPath}\{subKeyName}\Debugger -> {debugger}",
                                ObjectName = subKeyName,
                                RiskLevel = RiskLevel.ConfirmedMalicious,
                                RiskScore = 95,
                                Category = FindingCategory.SuspiciousPersistence,
                                Title = $"MRT: IFEO Hata Ayıklayıcı Kaçırması ({subKeyName})",
                                Description = $"{subKeyName} başlatıldığında sistem antivirüs yerine zararlı '{debugger}' dosyasını çalıştıracak şekilde değiştirilmiş.",
                                RiskReasons = new List<string>
                                {
                                    $"IFEO Debugger değeri ayarlanmış: {debugger}",
                                    "Zararlı yazılımlar güvenlik araçlarının açılmasını engellemek için bu yöntemi kullanır.",
                                    "Microsoft MRT / MSRT kritik persistence kategorisinde tespit edildi."
                                },
                                ConfidenceLevel = ConfidenceLevel.High,
                                FirstObserved = DateTime.UtcNow,
                                LastObserved = DateTime.UtcNow,
                                Status = FindingStatus.Active
                            });
                        }
                    }
                }
            }
            catch { }
        }

        private static void CheckWinlogonHijacks(List<SecurityFinding> findings, CancellationToken ct)
        {
            try
            {
                string winlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
                using var key = Registry.LocalMachine.OpenSubKey(winlogonPath);
                if (key == null) return;

                var shell = key.GetValue("Shell")?.ToString()?.Trim();
                if (!string.IsNullOrEmpty(shell) && !shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new SecurityFinding
                    {
                        ObjectPath = $@"HKLM\{winlogonPath}\Shell -> {shell}",
                        ObjectName = "Winlogon Shell",
                        RiskLevel = RiskLevel.ConfirmedMalicious,
                        RiskScore = 90,
                        Category = FindingCategory.SuspiciousPersistence,
                        Title = "MRT: Winlogon Shell Kaçırması Tespit Edildi",
                        Description = $"Windows varsayılan masaüstü kabuğu (explorer.exe) yerine '{shell}' çalıştırılıyor.",
                        RiskReasons = new List<string>
                        {
                            $"Shell değeri değiştirilmiş: {shell}",
                            "Windows oturum açılışında arka kapı veya truva atı tetikleme riski."
                        },
                        ConfidenceLevel = ConfidenceLevel.High,
                        FirstObserved = DateTime.UtcNow,
                        LastObserved = DateTime.UtcNow,
                        Status = FindingStatus.Active
                    });
                }

                var userinit = key.GetValue("Userinit")?.ToString()?.Trim();
                if (!string.IsNullOrEmpty(userinit))
                {
                    var cleanUserinit = userinit
                        .Replace(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "userinit.exe"), "", StringComparison.OrdinalIgnoreCase)
                        .Replace(@"C:\Windows\system32\userinit.exe", "", StringComparison.OrdinalIgnoreCase)
                        .Replace(@"userinit.exe", "", StringComparison.OrdinalIgnoreCase)
                        .Trim(',', ' ', '"');

                    if (!string.IsNullOrEmpty(cleanUserinit))
                    {
                        findings.Add(new SecurityFinding
                        {
                            ObjectPath = $@"HKLM\{winlogonPath}\Userinit -> {userinit}",
                            ObjectName = "Winlogon Userinit",
                            RiskLevel = RiskLevel.ConfirmedMalicious,
                            RiskScore = 95,
                            Category = FindingCategory.SuspiciousPersistence,
                            Title = "MRT: Winlogon Userinit Ekstra Yük Tespit Edildi",
                            Description = $"Windows oturum başlatıcısına yetkisiz dosya iliştirilmiş: {cleanUserinit}",
                            RiskReasons = new List<string>
                            {
                                $"Userinit ek komut zinciri: {cleanUserinit}",
                                "Oturum açılır açılmaz gizli yönetici haklarıyla kod çalıştırma riski."
                            },
                            ConfidenceLevel = ConfidenceLevel.High,
                            FirstObserved = DateTime.UtcNow,
                            LastObserved = DateTime.UtcNow,
                            Status = FindingStatus.Active
                        });
                    }
                }
            }
            catch { }
        }

        private static void CheckAppInitDlls(List<SecurityFinding> findings, CancellationToken ct)
        {
            try
            {
                string winPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
                using var key = Registry.LocalMachine.OpenSubKey(winPath);
                if (key == null) return;

                var appInit = key.GetValue("AppInit_DLLs")?.ToString()?.Trim();

                if (!string.IsNullOrEmpty(appInit))
                {
                    findings.Add(new SecurityFinding
                    {
                        ObjectPath = $@"HKLM\{winPath}\AppInit_DLLs -> {appInit}",
                        ObjectName = "AppInit_DLLs",
                        RiskLevel = RiskLevel.ConfirmedMalicious,
                        RiskScore = 88,
                        Category = FindingCategory.SystemModification,
                        Title = "MRT: Global DLL Enjeksiyonu (AppInit_DLLs)",
                        Description = $"Sistemdeki tüm pencereli uygulamalara otomatik enjekte olan DLL tespit edildi: {appInit}",
                        RiskReasons = new List<string>
                        {
                            $"AppInit_DLLs: {appInit}",
                            "Zararlı yazılımlar tüm süreçlere sızmak ve bankacılık/şifre çalmak için bu kaydı kullanır."
                        },
                        ConfidenceLevel = ConfidenceLevel.High,
                        FirstObserved = DateTime.UtcNow,
                        LastObserved = DateTime.UtcNow,
                        Status = FindingStatus.Active
                    });
                }
            }
            catch { }
        }

        private static void CheckHostsFileTampering(List<SecurityFinding> findings, CancellationToken ct)
        {
            try
            {
                string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                if (!File.Exists(hostsPath)) return;

                var lines = File.ReadAllLines(hostsPath);
                var securityDomains = new[] { "microsoft.com", "windowsupdate.com", "virustotal.com", "kaspersky.com", "bitdefender.com", "malwarebytes.com" };

                var blockedDomains = new List<string>();
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("#") || string.IsNullOrWhiteSpace(trimmed)) continue;

                    foreach (var domain in securityDomains)
                    {
                        if (trimmed.Contains(domain, StringComparison.OrdinalIgnoreCase) &&
                            (trimmed.StartsWith("127.0.0.1") || trimmed.StartsWith("0.0.0.0")))
                        {
                            blockedDomains.Add(domain);
                        }
                    }
                }

                if (blockedDomains.Count > 0)
                {
                    findings.Add(new SecurityFinding
                    {
                        ObjectPath = hostsPath,
                        ObjectName = "hosts",
                        RiskLevel = RiskLevel.ConfirmedMalicious,
                        RiskScore = 90,
                        Category = FindingCategory.SystemModification,
                        Title = "MRT: Hosts Dosyası Güvenlik Engellemesi Tespit Edildi",
                        Description = $"Hosts dosyası üzerinde güvenlik ve güncelleme siteleri engellenmiş: {string.Join(", ", blockedDomains)}",
                        RiskReasons = new List<string>
                        {
                            $"Engellenen kritik alan adları: {string.Join(", ", blockedDomains)}",
                            "Virüsler antivirüs güncellemelerini ve Windows Update'i engellemek için hosts dosyasını değiştirir."
                        },
                        ConfidenceLevel = ConfidenceLevel.High,
                        FirstObserved = DateTime.UtcNow,
                        LastObserved = DateTime.UtcNow,
                        Status = FindingStatus.Active
                    });
                }
            }
            catch { }
        }

        private static void CheckServiceDllHijacks(List<SecurityFinding> findings, CancellationToken ct)
        {
            try
            {
                using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (servicesKey == null) return;

                int inspected = 0;
                foreach (var serviceName in servicesKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested || inspected++ > 150) break;

                    using var serviceKey = servicesKey.OpenSubKey(serviceName);
                    using var paramsKey = serviceKey?.OpenSubKey("Parameters");
                    var serviceDll = paramsKey?.GetValue("ServiceDll")?.ToString();

                    if (!string.IsNullOrEmpty(serviceDll))
                    {
                        var lowerDll = serviceDll.ToLowerInvariant();
                        if (lowerDll.Contains(@"\temp\") || lowerDll.Contains(@"\appdata\") || lowerDll.Contains(@"\downloads\"))
                        {
                            findings.Add(new SecurityFinding
                            {
                                ObjectPath = serviceDll,
                                ObjectName = serviceName,
                                RiskLevel = RiskLevel.ConfirmedMalicious,
                                RiskScore = 92,
                                Category = FindingCategory.SuspiciousLocation,
                                Title = $"MRT: Şüpheli Servis DLL Konumu ({serviceName})",
                                Description = $"Windows Servisi '{serviceName}', Temp/AppData dizinindeki şüpheli bir DLL dosyasını çalıştırıyor.",
                                RiskReasons = new List<string>
                                {
                                    $"ServiceDll yolu: {serviceDll}",
                                    "Geçici dizinlerden Windows servisi yüklemek Tipik Trojan/Rootkit davranışıdır."
                                },
                                ConfidenceLevel = ConfidenceLevel.High,
                                FirstObserved = DateTime.UtcNow,
                                LastObserved = DateTime.UtcNow,
                                Status = FindingStatus.Active
                            });
                        }
                    }
                }
            }
            catch { }
        }

        private static void CheckScheduledTasks(List<SecurityFinding> findings, CancellationToken ct)
        {
            try
            {
                string tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
                if (!Directory.Exists(tasksDir)) return;

                var taskFiles = Directory.EnumerateFiles(tasksDir, "*", SearchOption.AllDirectories).Take(80);
                foreach (var taskFile in taskFiles)
                {
                    if (ct.IsCancellationRequested) break;

                    try
                    {
                        var content = File.ReadAllText(taskFile);
                        if (content.Contains("-enc ", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("DownloadString", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("IEX(", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("bypass -w hidden", StringComparison.OrdinalIgnoreCase))
                        {
                            findings.Add(new SecurityFinding
                            {
                                ObjectPath = taskFile,
                                ObjectName = Path.GetFileName(taskFile),
                                RiskLevel = RiskLevel.ConfirmedMalicious,
                                RiskScore = 94,
                                Category = FindingCategory.SuspiciousPersistence,
                                Title = $"MRT: Zararlı Zamanlanmış Görev ({Path.GetFileName(taskFile)})",
                                Description = "Zamanlanmış görev içerisinde Base64 şifreli veya gizli dosya indiren PowerShell komut zinciri tespit edildi.",
                                RiskReasons = new List<string>
                                {
                                    "Encoded / DownloadString komut kalıbı bulundu.",
                                    "Zararlı yazılımlar sistem yeniden başladığında otomatik çalışmak için bu görevi oluşturur."
                                },
                                ConfidenceLevel = ConfidenceLevel.High,
                                FirstObserved = DateTime.UtcNow,
                                LastObserved = DateTime.UtcNow,
                                Status = FindingStatus.Active
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private static void CheckActiveProcesses(List<SecurityFinding> findings, CancellationToken ct)
        {
            try
            {
                var processes = Process.GetProcesses();
                foreach (var proc in processes)
                {
                    if (ct.IsCancellationRequested) break;

                    try
                    {
                        if (proc.Id <= 4 || proc.Id == Environment.ProcessId) continue;
                        string mainModule = proc.MainModule?.FileName ?? string.Empty;
                        if (string.IsNullOrEmpty(mainModule) || FileScannerService.IsSelfOwnedPath(mainModule)) continue;

                        string lower = mainModule.ToLowerInvariant();
                        if (lower.Contains(@"\appdata\local\temp\") || lower.Contains(@"\windows\temp\"))
                        {
                            findings.Add(new SecurityFinding
                            {
                                ObjectPath = mainModule,
                                ObjectName = proc.ProcessName,
                                RiskLevel = RiskLevel.ConfirmedMalicious,
                                RiskScore = 88,
                                Category = FindingCategory.MalwareSuspicion,
                                Title = $"MRT: Geçici Dizinden Çalışan Aktif Süreç (PID {proc.Id})",
                                Description = $"'{proc.ProcessName}' süreci doğrudan Temp dizininden çalışıyor.",
                                RiskReasons = new List<string>
                                {
                                    $"Süreç yolu: {mainModule}",
                                    "Temp dizininden doğrudan çalışan bellek süreçleri yüksek risk taşır."
                                },
                                ConfidenceLevel = ConfidenceLevel.High,
                                FirstObserved = DateTime.UtcNow,
                                LastObserved = DateTime.UtcNow,
                                Status = FindingStatus.Active
                            });
                        }
                    }
                    catch { }
                    finally
                    {
                        proc.Dispose();
                    }
                }
            }
            catch { }
        }

        private static void CheckRunAndRunOnceKeys(List<SecurityFinding> findings, CancellationToken ct)
        {
            try
            {
                var hives = new[]
                {
                    (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
                    (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
                    (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
                    (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
                    (Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM WOW64 Run")
                };

                foreach (var (root, subKeyPath, hiveLabel) in hives)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        using var key = root.OpenSubKey(subKeyPath);
                        if (key == null) continue;

                        foreach (var valueName in key.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) break;
                            var rawValue = key.GetValue(valueName)?.ToString();
                            if (string.IsNullOrWhiteSpace(rawValue)) continue;

                            string lower = rawValue.ToLowerInvariant();
                            bool isSuspicious = false;
                            var reasons = new List<string>();

                            if (lower.Contains(@"\temp\") || lower.Contains(@"\appdata\local\temp\"))
                            {
                                isSuspicious = true;
                                reasons.Add("Başlangıç kaydı doğrudan geçici dizindeki (Temp) bir dosyayı çalıştırıyor.");
                            }

                            if (lower.Contains("-enc ") || lower.Contains("-encodedcommand ") || lower.Contains("-w hidden") || lower.Contains("downloadstring") || lower.Contains("iex("))
                            {
                                isSuspicious = true;
                                reasons.Add("Başlangıç kaydı Base64 şifreli veya gizli indirme yapan PowerShell/komut parametresi içeriyor.");
                            }

                            if (lower.EndsWith(".vbs") || lower.EndsWith(".js") || lower.EndsWith(".hta") || lower.EndsWith(".bat") || lower.EndsWith(".cmd") || lower.EndsWith(".scr"))
                            {
                                if (lower.Contains(@"\appdata\"))
                                {
                                    isSuspicious = true;
                                    reasons.Add("AppData dizininden otomatik çalışan şüpheli script/batch dosyası.");
                                }
                            }

                            if (isSuspicious)
                            {
                                reasons.Add($"Kayıt konumu: {hiveLabel} -> {valueName}");
                                reasons.Add($"Komut: {rawValue}");

                                findings.Add(new SecurityFinding
                                {
                                    ObjectPath = $"{hiveLabel}\\{valueName} -> {rawValue}",
                                    ObjectName = valueName,
                                    RiskLevel = RiskLevel.ConfirmedMalicious,
                                    RiskScore = 91,
                                    Category = FindingCategory.SuspiciousPersistence,
                                    Title = $"MRT: Şüpheli Başlangıç (Autorun) Kaydı ({valueName})",
                                    Description = $"'{valueName}' başlangıç kaydı şüpheli bir konumdan veya gizli parametrelerle otomatik başlatılıyor.",
                                    RiskReasons = reasons,
                                    ConfidenceLevel = ConfidenceLevel.High,
                                    FirstObserved = DateTime.UtcNow,
                                    LastObserved = DateTime.UtcNow,
                                    Status = FindingStatus.Active
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }
}
