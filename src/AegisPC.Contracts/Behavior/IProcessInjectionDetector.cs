using System.Collections.Generic;

namespace AegisPC.Contracts.Behavior
{
    /// <summary>
    /// Süreçler arası bellek enjeksiyonu, hollowing ve APC erken çalıştırma tekniklerini tespit eden analizci arayüzü.
    /// </summary>
    public interface IProcessInjectionDetector
    {
        ProcessInjectionEvaluation EvaluateApiSequence(int sourcePid, int targetPid, IEnumerable<string> observedApis, string sourceProcName = "", string targetProcName = "");
    }
}
