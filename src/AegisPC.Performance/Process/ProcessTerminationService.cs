using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using Microsoft.Extensions.Logging;

namespace AegisPC.Performance.Process
{
    public class ProcessTerminationResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public bool IsProtectedProcess { get; set; }
    }

    public class ProcessTerminationService
    {
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger<ProcessTerminationService>? _logger;

        public ProcessTerminationService(IAuditLogService? auditLogService = null, ILogger<ProcessTerminationService>? logger = null)
        {
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task<ProcessTerminationResult> TerminateProcessAsync(int pid, bool killTree = false, CancellationToken cancellationToken = default)
        {
            try
            {
                using var process = System.Diagnostics.Process.GetProcessById(pid);
                var processName = process.ProcessName;

                if (CriticalProcesses.IsCriticalProcess(processName))
                {
                    var msg = $"'{processName}' (PID: {pid}) bir Windows kritik sistem sürecidir ve sonlandırılması engellenmiştir.";
                    _logger?.LogWarning(msg);
                    if (_auditLogService != null)
                    {
                        await _auditLogService.LogActionAsync(
                            AuditAction.ProcessTerminated,
                            "Process",
                            processName,
                            null,
                            msg,
                            AuditResult.Denied,
                            "Critical system process protection",
                            cancellationToken);
                    }

                    return new ProcessTerminationResult
                    {
                        Success = false,
                        Message = msg,
                        IsProtectedProcess = true
                    };
                }

                process.Kill(entireProcessTree: killTree);
                await process.WaitForExitAsync(cancellationToken);

                var successMsg = $"'{processName}' (PID: {pid}) başarıyla sonlandırıldı.";
                _logger?.LogInformation(successMsg);

                if (_auditLogService != null)
                {
                    await _auditLogService.LogActionAsync(
                        AuditAction.ProcessTerminated,
                        "Process",
                        processName,
                        null,
                        killTree ? "Tüm süreç ağacı sonlandırıldı." : "Tek süreç sonlandırıldı.",
                        AuditResult.Success,
                        null,
                        cancellationToken);
                }

                return new ProcessTerminationResult
                {
                    Success = true,
                    Message = successMsg
                };
            }
            catch (ArgumentException)
            {
                return new ProcessTerminationResult
                {
                    Success = false,
                    Message = $"PID {pid} ile çalışan bir süreç bulunamadı veya süreç zaten sonlanmış."
                };
            }
            catch (Win32Exception ex)
            {
                var errorMsg = $"Erişim Windows tarafından reddedildi: {ex.Message}. Süreç Windows Defender, PPL veya sistem hakları tarafından korunuyor olabilir.";
                _logger?.LogWarning(ex, "Failed to terminate process {Pid}", pid);

                if (_auditLogService != null)
                {
                    await _auditLogService.LogActionAsync(
                        AuditAction.ProcessTerminated,
                        "Process",
                        $"PID_{pid}",
                        null,
                        errorMsg,
                        AuditResult.Denied,
                        ex.Message,
                        cancellationToken);
                }

                return new ProcessTerminationResult
                {
                    Success = false,
                    Message = errorMsg,
                    IsProtectedProcess = true
                };
            }
            catch (Exception ex)
            {
                var errorMsg = $"Süreç sonlandırılırken beklenmeyen hata oluştu: {ex.Message}";
                _logger?.LogError(ex, "Unexpected error terminating process {Pid}", pid);

                if (_auditLogService != null)
                {
                    await _auditLogService.LogActionAsync(
                        AuditAction.ProcessTerminated,
                        "Process",
                        $"PID_{pid}",
                        null,
                        errorMsg,
                        AuditResult.Failed,
                        ex.Message,
                        cancellationToken);
                }

                return new ProcessTerminationResult
                {
                    Success = false,
                    Message = errorMsg
                };
            }
        }

        public async Task<ProcessTerminationResult> TerminateProcessSafelyAsync(
            int pid,
            string? expectedExecutablePath = null,
            string? expectedProcessName = null,
            bool killTree = true,
            CancellationToken cancellationToken = default)
        {
            if (pid <= 4)
            {
                return new ProcessTerminationResult
                {
                    Success = false,
                    Message = $"PID {pid} sistem sürecidir ve sonlandırılamaz.",
                    IsProtectedProcess = true
                };
            }

            try
            {
                using var process = System.Diagnostics.Process.GetProcessById(pid);
                var processName = process.ProcessName;

                if (CriticalProcesses.IsCriticalProcess(processName))
                {
                    return new ProcessTerminationResult
                    {
                        Success = false,
                        Message = $"'{processName}' (PID: {pid}) bir Windows kritik sistem sürecidir ve sonlandırılması engellenmiştir.",
                        IsProtectedProcess = true
                    };
                }

                // Verify PID Reuse: if expected name or path provided, ensure process has not been replaced
                if (!string.IsNullOrEmpty(expectedProcessName) && !string.Equals(processName, expectedProcessName, StringComparison.OrdinalIgnoreCase))
                {
                    return new ProcessTerminationResult
                    {
                        Success = false,
                        Message = $"PID {pid} yeniden kullanılmış (Mevcut: '{processName}', Beklenen: '{expectedProcessName}'). Sonlandırma iptal edildi."
                    };
                }

                if (!string.IsNullOrEmpty(expectedExecutablePath))
                {
                    try
                    {
                        var actualPath = process.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(actualPath) && !string.Equals(actualPath, expectedExecutablePath, StringComparison.OrdinalIgnoreCase))
                        {
                            return new ProcessTerminationResult
                            {
                                Success = false,
                                Message = $"PID {pid} çalıştırılabilir dosya yolu uyuşmuyor ('{actualPath}' != '{expectedExecutablePath}'). PID reuse şüphesiyle sonlandırma iptal edildi."
                            };
                        }
                    }
                    catch { }
                }

                return await TerminateProcessAsync(pid, killTree, cancellationToken);
            }
            catch (ArgumentException)
            {
                return new ProcessTerminationResult
                {
                    Success = false,
                    Message = $"PID {pid} ile çalışan süreç bulunamadı veya zaten sonlanmış."
                };
            }
            catch (Exception ex)
            {
                return new ProcessTerminationResult
                {
                    Success = false,
                    Message = $"Süreç doğrulama hatası: {ex.Message}"
                };
            }
        }
    }
}
