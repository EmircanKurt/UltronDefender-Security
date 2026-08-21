using System;
using System.Collections.Generic;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Diagnostics.Crash
{
    public static class CrashReportBuilder
    {
        public static CrashReport Build(CrashEvent crashEvent)
        {
            var timeline = new List<TimelineEntry>();
            var factors = new List<string>();
            var actions = new List<string>();

            // Build Timeline
            timeline.Add(new TimelineEntry
            {
                Timestamp = crashEvent.OccurredAt.AddSeconds(-30),
                Category = "Kaynak Durumu",
                Description = crashEvent.CpuAtTime.HasValue 
                    ? $"Sistem CPU: %{crashEvent.CpuAtTime.Value:F1}" 
                    : "Sistem arka plan telemetrisi kaydedildi.",
                Severity = EventSeverity.Info,
                RelatedProcessName = crashEvent.ApplicationName
            });

            timeline.Add(new TimelineEntry
            {
                Timestamp = crashEvent.OccurredAt,
                Category = crashEvent.EventType switch
                {
                    CrashEventType.AppCrash => "Uygulama Çökmesi",
                    CrashEventType.AppHang => "Uygulama Yanıt Vermiyor (Hang)",
                    CrashEventType.BSOD => "Mavi Ekran (BSOD)",
                    CrashEventType.UnexpectedShutdown => "Beklenmeyen Kapanma",
                    _ => "Sistem Olayı"
                },
                Description = $"{crashEvent.ApplicationName} hata verdi (Event ID: {crashEvent.EventId}). {crashEvent.ExceptionCode}",
                Severity = EventSeverity.Error,
                RelatedProcessName = crashEvent.ApplicationName
            });

            timeline.Add(new TimelineEntry
            {
                Timestamp = crashEvent.OccurredAt.AddSeconds(2),
                Category = "Hata Raporlama",
                Description = "Windows Hata Bildirimi (WER) çökme raporunu kaydetti.",
                Severity = EventSeverity.Info,
                RelatedProcessName = crashEvent.ApplicationName
            });

            // Contributing factors
            if (!string.IsNullOrEmpty(crashEvent.AnalysisResult))
            {
                factors.AddRange(crashEvent.AnalysisResult.Split('\n', StringSplitOptions.RemoveEmptyEntries));
            }
            else
            {
                factors.Add("Uygulama belleğinde erişim hatası veya işlenmemiş bir yazılım istisnası oluştu.");
            }

            // Recommended actions
            actions.Add("Uygulamanın en güncel sürümüne sahip olduğunuzdan emin olun.");
            actions.Add("Uygulama çökmesi tekrarlanıyorsa, uygulamanın önbelleğini veya yapılandırmasını sıfırlamayı değerlendirebilirsiniz.");
            if (crashEvent.EventType == CrashEventType.BSOD || crashEvent.EventType == CrashEventType.UnexpectedShutdown)
            {
                actions.Add("Ekran kartı ve yonga seti sürücülerinizin güncel olduğundan emin olun.");
                actions.Add("Windows Bellek Tanılama aracı ile RAM sağlığını test edebilirsiniz.");
            }

            string summary = $"{crashEvent.ApplicationName} uygulamasında {crashEvent.OccurredAt:HH:mm:ss} zamanında " +
                (crashEvent.EventType == CrashEventType.AppHang ? "yanıt vermeme (donma)" : "beklenmeyen çökme") +
                " durumu kaydedildi.";

            return new CrashReport
            {
                CrashEvent = crashEvent,
                TimelineEntries = timeline,
                ContributingFactors = factors,
                RecommendedActions = actions,
                ConfidenceLevel = crashEvent.ConfidenceLevel,
                Summary = summary
            };
        }
    }
}
