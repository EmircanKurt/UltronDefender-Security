using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Network;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Network
{
    /// <summary>
    /// Ağ akışlarını (WFP Telemetrisi) süreç kimliği, ikili adı ve zamansal desenlerle
    /// korele ederek C2 Beaconing ve LOLBin ağ çıkışlarını tespit eden motor.
    /// </summary>
    public class NetworkProcessCorrelator : INetworkProcessCorrelator, IWfpTelemetryEngine
    {
        private readonly ConcurrentBag<NetworkFlowEvent> _flows = new();
        private readonly ILogger<NetworkProcessCorrelator>? _logger;

        private static readonly HashSet<string> SuspiciousNetworkLolbins = new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe", "bitsadmin.exe",
            "rundll32.exe", "regsvr32.exe", "mshta.exe", "cscript.exe", "wscript.exe", "wmic.exe"
        };

        public event Action<NetworkFlowEvent>? OnFlowRecorded;

        public NetworkProcessCorrelator(ILogger<NetworkProcessCorrelator>? logger = null)
        {
            _logger = logger;
        }

        public void IngestNetworkFlow(NetworkFlowEvent flow)
        {
            if (flow == null) return;
            _flows.Add(flow);
            OnFlowRecorded?.Invoke(flow);
        }

        public NetworkConnectionVerdict CorrelateFlow(NetworkFlowEvent flow)
        {
            var verdict = new NetworkConnectionVerdict();
            if (flow == null) return verdict;

            var procName = System.IO.Path.GetFileName(flow.ProcessName).ToLowerInvariant();
            if (!procName.EndsWith(".exe")) procName += ".exe";

            // 1. LOLBin Dış Ağ Bağlantı Anomalisi (Komut satırı / Betik doğrudan C2'ye bağlanıyor)
            if (SuspiciousNetworkLolbins.Contains(procName) && !IsLocalOrPrivateIp(flow.RemoteAddress))
            {
                verdict.IsSuspicious = true;
                verdict.RiskScore += 45;
                verdict.ThreatTitle = $"🚨 LOLBin Ağ Anomalisi: {procName}";
                verdict.Evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.BehaviorNetwork,
                    RuleName = "NET_LOLBIN_OUTBOUND_C2",
                    ScoreContribution = 45,
                    Confidence = EvidenceConfidence.High,
                    Description = $"Sistem komut/betik aracı '{procName}' (PID: {flow.ProcessId}) harici IP adresine ({flow.RemoteAddress}:{flow.RemotePort}) bağlandı."
                });
            }

            // 2. C2 Beaconing (Düzenli Zaman Aralıklı Bağlantı Deseni)
            var recentProcFlows = _flows
                .Where(f => f.ProcessId == flow.ProcessId && f.RemoteAddress == flow.RemoteAddress)
                .OrderBy(f => f.TimestampUtc)
                .ToList();

            if (recentProcFlows.Count >= 4)
            {
                var intervals = new List<double>();
                for (int i = 1; i < recentProcFlows.Count; i++)
                {
                    intervals.Add((recentProcFlows[i].TimestampUtc - recentProcFlows[i - 1].TimestampUtc).TotalSeconds);
                }

                double avg = intervals.Average();
                double variance = intervals.Select(v => Math.Pow(v - avg, 2)).Average();
                double stdDev = Math.Sqrt(variance);

                // Düşük standart sapma = Düzenli periyodik sinyal (Beaconing)
                if (stdDev < 2.0 && avg > 0.5 && avg < 120.0)
                {
                    verdict.IsSuspicious = true;
                    verdict.IsC2Beaconing = true;
                    verdict.RiskScore = Math.Max(verdict.RiskScore, 85);
                    verdict.ThreatTitle = $"🚨 C2 Beaconing Tehdidi: {flow.ProcessName}";
                    verdict.Evidences.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.BehaviorNetwork,
                        RuleName = "NET_C2_BEACONING_PATTERN",
                        ScoreContribution = 50,
                        Confidence = EvidenceConfidence.High,
                        Description = $"Süreç düzenli zaman aralıklarıyla ({avg:F1} sn ±{stdDev:F1}s) C2 sunucusuna sinyal gönderiyor (MITRE T1071)."
                    });
                }
            }

            verdict.RiskScore = Math.Min(100, verdict.RiskScore);
            if (verdict.IsSuspicious)
            {
                verdict.Explanation = $"Ağ bağlantısı şüpheli sinyal içeriyor: {flow.ProcessName} ➔ {flow.RemoteAddress}:{flow.RemotePort}";
            }

            return verdict;
        }

        public IReadOnlyList<NetworkFlowEvent> GetProcessFlowHistory(int pid, TimeSpan window)
        {
            var cutoff = DateTime.UtcNow - window;
            return _flows
                .Where(f => f.ProcessId == pid && f.TimestampUtc >= cutoff)
                .OrderBy(f => f.TimestampUtc)
                .ToList();
        }

        private static bool IsLocalOrPrivateIp(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return true;
            if (ip is "127.0.0.1" or "::1" or "localhost") return true;
            if (ip.StartsWith("10.") || ip.StartsWith("192.168.") || ip.StartsWith("172.16.") || ip.StartsWith("169.254.")) return true;
            return false;
        }
    }
}
