using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Diagnostics.Correlation
{
    public class CorrelationResult
    {
        public List<string> ContributingFactors { get; set; } = new();
        public List<TimelineEntry> Timeline { get; set; } = new();
        public double ResourcePressureScore { get; set; }
    }

    public class CorrelationEngine : ICorrelationEngine
    {
        private readonly ILogger<CorrelationEngine>? _logger;

        public CorrelationEngine(ILogger<CorrelationEngine>? logger = null)
        {
            _logger = logger;
        }

        public Task CorrelateEventAsync(CrashEvent crashEvent, TimeSpan window, CancellationToken cancellationToken = default)
        {
            // Analyze crash event characteristics
            var factors = new List<string>();

            if (crashEvent.CpuAtTime.HasValue && crashEvent.CpuAtTime.Value > 80.0)
            {
                factors.Add($"Olay anında toplam işlemci kullanımı %{crashEvent.CpuAtTime.Value:F1} seviyesindeydi. Yüksek CPU yükü donmaya veya gecikmeye katkıda bulunmuş olabilir.");
            }

            if (crashEvent.MemoryAtTime.HasValue && crashEvent.MemoryAtTime.Value > (1024L * 1024L * 1024L * 2)) // >2GB
            {
                double gb = crashEvent.MemoryAtTime.Value / (1024.0 * 1024.0 * 1024.0);
                factors.Add($"Uygulama çökme anında yaklaşık {gb:F1} GB bellek tüketiyordu. Yüksek bellek kullanımı veya sızıntı kararsızlığa katkıda bulunmuş olabilir.");
            }

            if (!string.IsNullOrEmpty(crashEvent.ExceptionCode))
            {
                if (crashEvent.ExceptionCode.Equals("0xc0000005", StringComparison.OrdinalIgnoreCase))
                {
                    factors.Add("Hata kodu 0xC0000005 (Access Violation) tespit edildi. Uygulama geçersiz bir bellek adresine erişmeye çalıştı.");
                }
                else if (crashEvent.ExceptionCode.Equals("0xc00000fd", StringComparison.OrdinalIgnoreCase))
                {
                    factors.Add("Hata kodu 0xC00000FD (Stack Overflow) tespit edildi. Uygulama içinde sonsuz döngü veya aşırı derin özyineleme gerçekleşmiş olabilir.");
                }
            }

            if (factors.Count == 0)
            {
                factors.Add("Olay anında sistem genelinde olağandışı bir donanım darboğazı tespit edilmedi. Hatanın uygulama içi bir istisnadan kaynaklanmış olması muhtemeldir.");
            }

            crashEvent.AnalysisResult = string.Join("\n• ", factors);
            return Task.CompletedTask;
        }
    }
}
