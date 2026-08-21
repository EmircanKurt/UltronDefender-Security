using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.AntiEvasion
{
    /// <summary>
    /// Süreç bellek alanlarını, kabuk kodu (shellcode) bellek tamponlarını,
    /// Inline Hooking ve Process Hollowing anomalilerini analiz eden bellek içi desen tarayıcısı arayüzü.
    /// </summary>
    public interface IMemoryPatternScanner
    {
        MemoryScanVerdict ScanBuffer(byte[] memoryBytes);
        Task<MemoryScanVerdict> ScanProcessMemoryAsync(int pid, CancellationToken cancellationToken = default);
        MemoryScanVerdict DetectInlineHooks(int pid, string dllPath = @"C:\Windows\System32\ntdll.dll");
        MemoryScanVerdict DetectProcessHollowing(int pid, string diskExecutablePath);
    }
}
