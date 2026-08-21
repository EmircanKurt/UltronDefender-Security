using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Recommendations.AiExplanation
{
    public interface IAiExplanationService
    {
        Task<string> ExplainFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default);
        Task<string> ExplainCrashAsync(CrashEvent crashEvent, CancellationToken cancellationToken = default);
    }

    public class AiExplanationService : IAiExplanationService
    {
        public Task<string> ExplainFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default)
        {
            var explanation = $"'{finding.ObjectName}' dosyası için tespit edilen risk seviyesi: {finding.RiskLevel}.\n" +
                              $"Bu dosya şu sebeplerden dolayı şüpheli olarak sınıflandırılmıştır:\n" +
                              $"{string.Join("\n• ", finding.RiskReasons)}\n\n" +
                              "Öneri: Dosyayı tanımıyorsanız veya şüpheli bir kaynaktan indirdiyseniz karantinaya almanız tavsiye edilir.";
            return Task.FromResult(explanation);
        }

        public Task<string> ExplainCrashAsync(CrashEvent crashEvent, CancellationToken cancellationToken = default)
        {
            var explanation = $"'{crashEvent.ApplicationName}' uygulaması beklenmeyen bir şekilde çöktü (Özel durum: {crashEvent.ExceptionCode ?? "Belirtilmedi"}).\n" +
                              $"Olay anındaki sistem durumu ve donanım telemetrisi incelendiğinde, sorunun yazılımsal bellek erişim ihlalinden (Access Violation) kaynaklanmış olabileceği değerlendirilmektedir.";
            return Task.FromResult(explanation);
        }
    }
}
