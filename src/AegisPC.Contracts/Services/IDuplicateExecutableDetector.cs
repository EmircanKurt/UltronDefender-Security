using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services
{
    /// <summary>
    /// Klasörde veya sistemde birden çok UltronDefender.exe/AegisPC.exe publish kopyasını tespit edip kullanıcıyı tek güncel konuma yönlendiren dedektör arayüzü.
    /// </summary>
    public interface IDuplicateExecutableDetector
    {
        DuplicateExecutableResult CheckForDuplicates(string? searchRoot = null, string? currentExePath = null);
    }
}
