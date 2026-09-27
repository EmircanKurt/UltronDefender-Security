using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Performance.Process;

/// <summary>Describes the observed root-process result, not proof that every descendant has exited.</summary>
public class ProcessTerminationResult
{
    /// <summary>True only after the selected root process is observed to have exited.</summary>
    public bool Success { get; set; }
    /// <summary>Explains identity rejection, Windows permission limits, or confirmed root exit to the user.</summary>
    public string Message { get; set; } = string.Empty;
    /// <summary>Indicates a safety or access denial; does not assert that Windows PPL was positively identified.</summary>
    public bool IsProtectedProcess { get; set; }
    /// <summary>Returns the Windows error code when available without inferring malware or bypassing access restrictions.</summary>
    public int? NativeErrorCode { get; set; }
    /// <summary>Distinguishes a sent request with unconfirmed exit from a pre-action rejection.</summary>
    public bool TerminationRequested { get; set; }
}

/// <summary>
/// Performs explicit user-requested process termination through Windows access checks.
/// Selected-process requests require matching executable path and creation time on the same retained handle.
/// Critical/self processes are denied; this service never changes privileges or bypasses protected-process restrictions.
/// </summary>
public class ProcessTerminationService
{
    private readonly IAuditLogService? _auditLogService;
    private readonly ILogger<ProcessTerminationService>? _logger;

    /// <summary>Creates the process action service with optional audit persistence and diagnostic logging.</summary>
    public ProcessTerminationService(IAuditLogService? auditLogService = null, ILogger<ProcessTerminationService>? logger = null)
    {
        _auditLogService = auditLogService;
        _logger = logger;
    }

    /// <summary>
    /// Terminates an explicitly supplied current PID with critical/self protection and a bounded root-exit wait.
    /// It cannot validate a stale UI selection; use TerminateSelectedProcessAsync for process-list actions.
    /// </summary>
    public Task<ProcessTerminationResult> TerminateProcessAsync(int pid, bool killTree = false, CancellationToken cancellationToken = default)
        => ExecuteAsync(pid, killTree, null, null, null, cancellationToken);

    /// <summary>
    /// Rejects stale or unverifiable selections before requesting termination; validates path and start time on one handle.
    /// A five-second wait limits hangs. Descendants are best-effort, without bypassing Windows access controls.
    /// </summary>
    public Task<ProcessTerminationResult> TerminateSelectedProcessAsync(ProcessInfo selectedProcess, bool killTree = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selectedProcess);
        if (selectedProcess.StartTime == DateTime.MinValue || string.IsNullOrWhiteSpace(selectedProcess.ExecutablePath))
            return Task.FromResult(new ProcessTerminationResult { Message = "Seçilen sürecin başlangıç zamanı veya dosya yolu doğrulanamıyor. Listeyi yenileyin; işlem uygulanmadı." });
        return ExecuteAsync(selectedProcess.PID, killTree, selectedProcess.ExecutablePath,
            selectedProcess.Name, selectedProcess.StartTime, cancellationToken);
    }

    /// <summary>
    /// Preserves legacy name/path verification without reopening the PID after validation.
    /// Read failures reject the action; without a creation-time snapshot this API cannot verify stale selection fully.
    /// </summary>
    public Task<ProcessTerminationResult> TerminateProcessSafelyAsync(int pid, string? expectedExecutablePath = null,
        string? expectedProcessName = null, bool killTree = true, CancellationToken cancellationToken = default)
        => ExecuteAsync(pid, killTree, expectedExecutablePath, expectedProcessName, null, cancellationToken);

    private async Task<ProcessTerminationResult> ExecuteAsync(int pid, bool killTree, string? expectedPath,
        string? expectedName, DateTime? expectedStart, CancellationToken cancellationToken)
    {
        if (pid <= 4 || pid == Environment.ProcessId)
            return await ReportAsync(new() { IsProtectedProcess = true,
                Message = $"PID {pid} sistem veya Ultron'un kendi sürecidir; sonlandırma engellendi." }, pid);

        bool requested = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            // Force association before identity checks. Kill and exit-wait retain the same Windows process object.
            var handle = process.SafeHandle;
            string actualPath = ReadImagePath(handle);
            string actualName = Path.GetFileNameWithoutExtension(actualPath);
            if (!IsProcessCritical(handle, out bool critical)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (critical || CriticalProcesses.IsCriticalProcess(actualName))
                return await ReportAsync(new() { IsProtectedProcess = true,
                    Message = $"'{actualName}' (PID: {pid}) kritik sistem süreci olarak korunuyor; sonlandırılmadı." }, pid);

            if (!IdentityMatches(process, actualPath, actualName, expectedPath, expectedName, expectedStart))
                return await ReportAsync(new() { Message = $"PID {pid} seçilen süreç kimliğiyle uyuşmuyor (PID yeniden kullanılmış olabilir). Listeyi yenileyin; işlem uygulanmadı." }, pid);

            cancellationToken.ThrowIfCancellationRequested();
            process.Kill(entireProcessTree: killTree);
            requested = true;
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            wait.CancelAfter(TimeSpan.FromSeconds(5));
            await process.WaitForExitAsync(wait.Token);
            return await ReportAsync(new() { Success = true, TerminationRequested = true,
                Message = killTree
                    ? $"'{actualName}' (PID: {pid}) sonlandı. Alt süreçler için sonlandırma istendi; tüm alt süreçlerin kapanması doğrulanmadı."
                    : $"'{actualName}' (PID: {pid}) sonlandırıldı ve çıkışı doğrulandı." }, pid);
        }
        catch (OperationCanceledException) when (requested)
        {
            return await ReportAsync(new() { TerminationRequested = true,
                Message = $"PID {pid} için sonlandırma istendi, ancak bekleme iptal oldu veya 5 saniyede çıkış doğrulanamadı. Listeyi yenileyin." }, pid);
        }
        catch (OperationCanceledException) { throw; }
        catch (ArgumentException ex)
        {
            _logger?.LogInformation(ex, "Process {Pid} no longer exists", pid);
            return await ReportAsync(new() { Message = $"PID {pid} bulunamadı veya süreç zaten sonlandı." }, pid);
        }
        catch (Win32Exception ex)
        {
            _logger?.LogWarning(ex, "Windows rejected process action for PID {Pid}, native error {Error}", pid, ex.NativeErrorCode);
            return await ReportAsync(new() { IsProtectedProcess = ex.NativeErrorCode == 5, NativeErrorCode = ex.NativeErrorCode,
                TerminationRequested = requested,
                Message = ex.NativeErrorCode == 5
                    ? $"Windows erişimi reddetti (hata 5). Yönetici izni gerekebilir veya süreç PPL/ACL ile korunuyor olabilir. Koruma atlatılmadı. {ex.Message}"
                    : $"Windows süreç işlemini tamamlayamadı (hata {ex.NativeErrorCode}): {ex.Message}" }, pid);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Process action failed for PID {Pid}", pid);
            return await ReportAsync(new() { TerminationRequested = requested,
                Message = $"Süreç işlemi tamamlanamadı: {ex.Message}. Sonlandırıldığı doğrulanmadı." }, pid);
        }
    }

    private static bool IdentityMatches(System.Diagnostics.Process process, string actualPath, string actualName,
        string? expectedPath, string? expectedName, DateTime? expectedStart)
    {
        if (!string.IsNullOrWhiteSpace(expectedName) && !actualName.Equals(
                Path.GetFileNameWithoutExtension(expectedName), StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrWhiteSpace(expectedPath) && !Path.GetFullPath(actualPath).Equals(
                Path.GetFullPath(expectedPath), StringComparison.OrdinalIgnoreCase)) return false;
        return !expectedStart.HasValue || process.StartTime.ToUniversalTime() == expectedStart.Value.ToUniversalTime();
    }

    private static string ReadImagePath(SafeProcessHandle handle)
    {
        var path = new StringBuilder(32768);
        int size = path.Capacity;
        if (!QueryFullProcessImageName(handle, 0, path, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (size == 0) throw new InvalidOperationException("Windows did not provide the process executable identity.");
        return path.ToString();
    }

    private async Task<ProcessTerminationResult> ReportAsync(ProcessTerminationResult result, int pid)
    {
        _logger?.LogInformation("Process action for PID {Pid}: success={Success}, requested={Requested}, protected={Protected}",
            pid, result.Success, result.TerminationRequested, result.IsProtectedProcess);
        if (_auditLogService == null) return result;
        try
        {
            await _auditLogService.LogActionAsync(AuditAction.ProcessTerminated, "Process", $"PID_{pid}", null,
                result.Message, result.Success ? AuditResult.Success : result.IsProtectedProcess ? AuditResult.Denied : AuditResult.Failed,
                result.Success ? null : result.Message, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to persist process-action audit for PID {Pid}", pid);
            result.Message += " Denetim kaydı yazılamadı; gözlenen süreç sonucu değiştirilmedi.";
        }
        return result;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryFullProcessImageNameW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessCritical(SafeProcessHandle process, [MarshalAs(UnmanagedType.Bool)] out bool critical);
}
