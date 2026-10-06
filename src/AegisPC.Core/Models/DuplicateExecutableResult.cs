using System.Collections.Generic;

namespace AegisPC.Core.Models
{
    /// <summary>
    /// Aynı makinede veya dizinde birden çok UltronDefender/AegisPC kopyası algılandığında üretilen analiz sonucu.
    /// </summary>
    public class DuplicateExecutableResult
    {
        public bool HasDuplicates { get; set; }
        public string RunningExecutablePath { get; set; } = string.Empty;
        public string RecommendedExecutablePath { get; set; } = string.Empty;
        public List<string> DuplicateExecutablePaths { get; set; } = new();
        public string AdvisoryMessage { get; set; } = string.Empty;
    }
}
