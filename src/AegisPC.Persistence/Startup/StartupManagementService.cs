using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace AegisPC.Persistence.Startup
{
    public class StartupManagementService
    {
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger<StartupManagementService>? _logger;

        public StartupManagementService(IAuditLogService? auditLogService = null, ILogger<StartupManagementService>? logger = null)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task<bool> DisableStartupItemAsync(StartupItem item, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. Startup folder shortcut handling
                if (item.Source.Contains("Folder", StringComparison.OrdinalIgnoreCase) || item.Source.Contains("Klasör", StringComparison.OrdinalIgnoreCase))
                {
                    if (File.Exists(item.FilePath))
                    {
                        var disabledPath = item.FilePath + ".disabled";
                        File.Move(item.FilePath, disabledPath, true);
                        item.FilePath = disabledPath;
                        item.IsEnabled = false;
                        return true;
                    }
                }

                // 2. Scheduled Tasks handling
                if (item.Source.Contains("Task", StringComparison.OrdinalIgnoreCase) || item.Source.Contains("Görev", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = "schtasks.exe",
                            Arguments = $"/Change /TN \"{item.Name}\" /DISABLE",
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };
                        using var proc = Process.Start(psi);
                        if (proc != null)
                        {
                            await proc.WaitForExitAsync(cancellationToken);
                            if (proc.ExitCode == 0)
                            {
                                item.IsEnabled = false;
                                return true;
                            }
                        }
                    }
                    catch { }
                }

                // 3. Registry HKCU
                if (!string.IsNullOrEmpty(item.RegistryPath) && item.RegistryPath.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase))
                {
                    var subKey = item.RegistryPath.Substring(5);
                    using var key = Registry.CurrentUser.OpenSubKey(subKey, writable: true);
                    if (key != null)
                    {
                        var val = key.GetValue(item.Name);
                        if (val != null)
                        {
                            item.BackupValue = val.ToString();
                            key.DeleteValue(item.Name);
                            item.IsEnabled = false;

                            if (_auditLogService != null)
                            {
                                await _auditLogService.LogActionAsync(
                                    AuditAction.StartupDisabled,
                                    "StartupItem",
                                    item.Name,
                                    item.FilePath,
                                    $"Başlangıç girdisi devre dışı bırakıldı (HKCU). Yedek: {item.BackupValue}",
                                    AuditResult.Success,
                                    null,
                                    cancellationToken);
                            }

                            return true;
                        }
                    }
                }
                else if (!string.IsNullOrEmpty(item.RegistryPath) && item.RegistryPath.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
                {
                    // For HKLM, write to HKCU StartupApproved\Run as disabled marker (0x03 byte flags)
                    using var approvedKey = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run");
                    if (approvedKey != null)
                    {
                        var disabledBytes = new byte[] { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                        approvedKey.SetValue(item.Name, disabledBytes, RegistryValueKind.Binary);
                        item.IsEnabled = false;
                    }
                }

                // Save to persistent disabled storage
                var disabledSet = RegistryStartupScanner.LoadPersistentDisabledItems();
                if (!string.IsNullOrEmpty(item.Name)) disabledSet.Add(item.Name);
                if (!string.IsNullOrEmpty(item.FilePath)) disabledSet.Add(item.FilePath);
                RegistryStartupScanner.SavePersistentDisabledItems(disabledSet);

                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to disable startup item {Name}", item.Name);
                return false;
            }
        }

        public async Task<bool> EnableStartupItemAsync(StartupItem item, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. Startup folder shortcut handling
                if (item.FilePath.EndsWith(".disabled", StringComparison.OrdinalIgnoreCase))
                {
                    var enabledPath = item.FilePath.Substring(0, item.FilePath.Length - 9);
                    File.Move(item.FilePath, enabledPath, true);
                    item.FilePath = enabledPath;
                    item.IsEnabled = true;
                    return true;
                }

                // 2. Scheduled Tasks handling
                if (item.Source.Contains("Task", StringComparison.OrdinalIgnoreCase) || item.Source.Contains("Görev", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = "schtasks.exe",
                            Arguments = $"/Change /TN \"{item.Name}\" /ENABLE",
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };
                        using var proc = Process.Start(psi);
                        if (proc != null)
                        {
                            await proc.WaitForExitAsync(cancellationToken);
                            if (proc.ExitCode == 0)
                            {
                                item.IsEnabled = true;
                                return true;
                            }
                        }
                    }
                    catch { }
                }

                // 3. Restore HKCU Value if backup available
                if (!string.IsNullOrEmpty(item.RegistryPath) && item.RegistryPath.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase))
                {
                    var subKey = item.RegistryPath.Substring(5);
                    using var key = Registry.CurrentUser.OpenSubKey(subKey, writable: true);
                    if (key != null && !string.IsNullOrEmpty(item.BackupValue))
                    {
                        key.SetValue(item.Name, item.BackupValue);
                        item.IsEnabled = true;
                        return true;
                    }
                }

                // 4. Remove from StartupApproved disabled list
                using (var approvedKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", writable: true))
                {
                    if (approvedKey != null)
                    {
                        approvedKey.DeleteValue(item.Name, false);
                    }
                }

                // Remove from persistent disabled storage
                var disabledSet = RegistryStartupScanner.LoadPersistentDisabledItems();
                if (!string.IsNullOrEmpty(item.Name)) disabledSet.Remove(item.Name);
                if (!string.IsNullOrEmpty(item.FilePath)) disabledSet.Remove(item.FilePath);
                RegistryStartupScanner.SavePersistentDisabledItems(disabledSet);

                item.IsEnabled = true;
                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to enable startup item {Name}", item.Name);
                return false;
            }
        }
    }
}
