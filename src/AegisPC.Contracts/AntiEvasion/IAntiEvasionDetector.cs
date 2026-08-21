using System.Collections.Generic;

namespace AegisPC.Contracts.AntiEvasion
{
    /// <summary>
    /// Statik ikili veya çalışan süreç üzerinde anti-debug, anti-vm, indirect syscall ve
    /// AMSI/ETW yamalama kaçınma tekniklerini tespit eden arayüz.
    /// </summary>
    public interface IAntiEvasionDetector
    {
        AntiEvasionEvaluation AnalyzeBinary(string filePath, byte[]? rawBytes = null);
        AntiEvasionEvaluation AnalyzeBehavior(int pid, string commandLine, IEnumerable<string>? loadedModules = null);
    }
}
