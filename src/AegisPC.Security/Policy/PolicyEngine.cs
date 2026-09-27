using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Policy;
using AegisPC.Contracts.Safety;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Safety;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Policy
{
    /// <summary>
    /// Ultron Defender (AegisPC) Merkezi Güvenlik Politika Motoru.
    /// "Bul" aşamasından "Engelle" aşamasına geçişi yönetir:
    /// - RiskScore >= 85 VE Category in {KnownMalwareHash, ConfirmedMalicious} -> Otomatik Karantina
    /// - RiskScore 60..84 -> Olay Merkezi uyarısı ("Uyarıldı")
    /// - SafetyGuard (ProtectedPathGuard/ReparsePointGuard/Microsoft imza kontrolü) her otomatik aksiyonun ÖNÜNDE çalışır;
    ///   imzalı Microsoft ikilisi veya korunan sistem dosyası ASLA otomatik karantinaya alınmaz.
    /// </summary>
    public class PolicyEngine : IPolicyEngine
    {
        private readonly ISettingsService? _settingsService;
        private readonly IQuarantineService? _quarantineService;
        private readonly ISecurityFindingService? _findingService;
        private readonly IProtectedPathGuard? _protectedPathGuard;
        private readonly IReparsePointGuard? _reparsePointGuard;
        private readonly ISignatureVerifier? _signatureVerifier;
        private readonly IAuditLogService? _auditLogService;
        private readonly INotificationAggregator? _notificationAggregator;
        private readonly IWindowsToastNotificationService? _toastService;
        private readonly IQuarantineUndoLogService? _undoLogService;
        private readonly IExclusionService? _exclusionService;
        private readonly ILogger<PolicyEngine>? _logger;

        public PolicyEngine(
            ISettingsService? settingsService = null,
            IQuarantineService? quarantineService = null,
            ISecurityFindingService? findingService = null,
            IProtectedPathGuard? protectedPathGuard = null,
            IReparsePointGuard? reparsePointGuard = null,
            ISignatureVerifier? signatureVerifier = null,
            IAuditLogService? auditLogService = null,
            INotificationAggregator? notificationAggregator = null,
            IWindowsToastNotificationService? toastService = null,
            IQuarantineUndoLogService? undoLogService = null,
            ILogger<PolicyEngine>? logger = null,
            IExclusionService? exclusionService = null)
        {
            _settingsService = settingsService;
            _quarantineService = quarantineService;
            _findingService = findingService;
            _protectedPathGuard = protectedPathGuard;
            _reparsePointGuard = reparsePointGuard;
            _signatureVerifier = signatureVerifier;
            _auditLogService = auditLogService;
            _notificationAggregator = notificationAggregator;
            _toastService = toastService;
            _undoLogService = undoLogService;
            _logger = logger;
            _exclusionService = exclusionService;
        }

        // Test ve geriye dönük uyumluluk için ek overload
        public PolicyEngine(
            ISettingsService? settingsService,
            IQuarantineService? quarantineService,
            ISecurityFindingService? findingService,
            IProtectedPathGuard? protectedPathGuard,
            IAuditLogService? auditLogService,
            IWindowsToastNotificationService? toastService,
            IProtectedPathGuard? pathGuardAlt,
            IReparsePointGuard? reparseGuardAlt,
            ISignatureVerifier? sigVerifierAlt,
            ILogger<PolicyEngine>? loggerAlt,
            IExclusionService? exclusionService)
            : this(settingsService, quarantineService, findingService, protectedPathGuard ?? pathGuardAlt, reparseGuardAlt, sigVerifierAlt, auditLogService, null, toastService, null, loggerAlt, exclusionService)
        {
        }

        public PolicyEvaluationResult EvaluateFinding(SecurityFinding finding, string? filePath = null)
        {
            string path = !string.IsNullOrWhiteSpace(filePath) ? filePath : finding.ObjectPath;

            if (_exclusionService != null && _exclusionService.IsExcluded(path, finding.SHA256))
            {
                return new PolicyEvaluationResult
                {
                    Action = PolicyDecisionAction.Allow,
                    Reason = "Dosya veya yol kullanıcı istisna listesinde (Exclusion) yer alıyor, otomatik müdahale yapılmadı.",
                    IsProtectedBySafetyGuard = false,
                    IsMicrosoftSigned = false,
                    QuarantinedSuccessfully = false
                };
            }

            bool isProtected = CheckSafetyGuardPath(path);

            return BuildEvaluation(finding, isProtected, isMicrosoftSigned: false);
        }

        public async Task<PolicyEvaluationResult> EvaluateFindingAsync(
            SecurityFinding finding,
            string? filePath = null,
            CancellationToken cancellationToken = default)
        {
            string path = !string.IsNullOrWhiteSpace(filePath) ? filePath : finding.ObjectPath;

            if (_exclusionService != null && _exclusionService.IsExcluded(path, finding.SHA256))
            {
                return new PolicyEvaluationResult
                {
                    Action = PolicyDecisionAction.Allow,
                    Reason = "Dosya veya yol kullanıcı istisna listesinde (Exclusion) yer alıyor, otomatik müdahale yapılmadı.",
                    IsProtectedBySafetyGuard = false,
                    IsMicrosoftSigned = false,
                    QuarantinedSuccessfully = false
                };
            }

            bool isProtected = CheckSafetyGuardPath(path);
            bool isMsSigned = false;

            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path) && _signatureVerifier != null)
            {
                try
                {
                    var sig = await _signatureVerifier.VerifySignatureAsync(path, cancellationToken);
                    if (sig != null && sig.IsSigned && sig.IsValid && TrustedSoftwarePolicy.IsTrustedOsPublisher(sig.Publisher))
                    {
                        isMsSigned = true;
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogTrace(ex, "Error verifying digital signature for policy evaluation: {Path}", path);
                }
            }

            return BuildEvaluation(finding, isProtected, isMsSigned);
        }

        public async Task<PolicyEvaluationResult> EnforcePolicyAsync(
            SecurityFinding finding,
            CancellationToken cancellationToken = default)
        {
            string path = finding.ObjectPath;
            string fileName = !string.IsNullOrWhiteSpace(finding.ObjectName) ? finding.ObjectName : Path.GetFileName(path);

            // Kontrol Noktası (d) [EN KRİTİK]:
            // Otomatik karantina (AutoQuarantine) istisnalı dosyaya ASLA uygulanmaz!
            if (_exclusionService != null && _exclusionService.IsExcluded(path, finding.SHA256))
            {
                _logger?.LogInformation("PolicyEngine: Dosya istisna listesinde olduğu için otomatik karantina engellendi: {Path}", path);
                return new PolicyEvaluationResult
                {
                    Action = PolicyDecisionAction.Allow,
                    Reason = "Dosya kullanıcı istisna listesinde (Exclusion) yer alıyor, otomatik karantina uygulanmadı.",
                    IsProtectedBySafetyGuard = false,
                    IsMicrosoftSigned = false,
                    QuarantinedSuccessfully = false
                };
            }

            var evaluation = await EvaluateFindingAsync(finding, finding.ObjectPath, cancellationToken);

            if (evaluation.Action == PolicyDecisionAction.AutoQuarantine)
            {
                if (_quarantineService != null && !string.IsNullOrWhiteSpace(path) && File.Exists(path))
                {
                    try
                    {
                        bool quarantined = _quarantineService is IContentBoundQuarantineService bound && await bound.TryQuarantineFileAsync(
                            path,
                            $"Otomatik Karantina (Risk Skoru: {finding.RiskScore}): {finding.Title}",
                            finding.SHA256 ?? string.Empty,
                            cancellationToken);

                        if (!quarantined)
                        {
                            _logger?.LogWarning("Automatic containment not applied; verified content may have changed or the vault is unavailable: {Path}", path);
                            _toastService?.ShowToast("⚠️ Karantina Uygulanamadı",
                                $"'{fileName}' için tespit kaydı korundu. Dosya kasaya alınmadı; yeniden tarama ve inceleme gerekiyor.", "Warning");
                            return evaluation with { Action = PolicyDecisionAction.Warn, Reason = "Doğrulanmış içerik karantinaya alınamadı; dosya engellendi sayılmaz.", QuarantinedSuccessfully = false };
                        }

                        if (quarantined)
                        {
                            finding.Status = FindingStatus.Resolved;
                            if (_findingService != null)
                            {
                                await _findingService.UpdateFindingAsync(finding, cancellationToken);
                            }

                            // Tekilleştirme hattı üzerinden bildirim
                            if (_notificationAggregator != null)
                            {
                                _notificationAggregator.PushThreatEvent(
                                    finding.Title,
                                    path,
                                    "Otomatik Karantinaya Alındı",
                                    isCritical: true);
                            }
                            else if (_toastService != null)
                            {
                                _toastService.ShowToast(
                                    "🛡️ Tehdit Engellendi ve Karantinaya Alındı",
                                    $"'{fileName}' zararlısı tespit edildi ve AES-256 kasaya kilitlendi.",
                                    "Danger");
                            }

                            if (_auditLogService != null)
                            {
                                try
                                {
                                    await _auditLogService.LogActionAsync(
                                        AuditAction.FileQuarantined,
                                        "PolicyEngine",
                                        finding.Title,
                                        path,
                                        $"Otomatik karantinaya alındı. Risk Skoru: {finding.RiskScore}, Kategori: {finding.Category}",
                                        AuditResult.Success,
                                        null,
                                        cancellationToken);
                                }
                                catch (Exception ex)
                                {
                                    _logger?.LogTrace(ex, "Audit log failed for quarantine");
                                }
                            }

                            if (_undoLogService != null)
                            {
                                try
                                {
                                    int quarantineId = Math.Abs(path.GetHashCode());
                                    if (_quarantineService != null)
                                    {
                                        var qItems = await _quarantineService.GetQuarantinedItemsAsync(cancellationToken);
                                        var matched = qItems.LastOrDefault(x => string.Equals(x.OriginalPath, path, StringComparison.OrdinalIgnoreCase));
                                        if (matched != null)
                                        {
                                            quarantineId = matched.Id;
                                        }
                                    }

                                    string decisionChain = $"Risk Skoru: {finding.RiskScore}/100, Kategori: {finding.Category}, Eşleşme: {finding.Title}, Politika: Otomatik Karantina";
                                    await _undoLogService.RecordQuarantineDecisionAsync(
                                        quarantineId,
                                        path,
                                        finding.RiskScore,
                                        finding.Title,
                                        decisionChain,
                                        cancellationToken);
                                }
                                catch (Exception undoEx)
                                {
                                    _logger?.LogTrace(undoEx, "Quarantine undo log recording failed.");
                                }
                            }

                            return evaluation with { QuarantinedSuccessfully = true };
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogError(ex, "Otomatik karantina infaz hatası: {Path}", path);
                    }
                }
            }
            else if (evaluation.Action == PolicyDecisionAction.Warn)
            {
                finding.Status = FindingStatus.Active;
                if (_findingService != null)
                {
                    await _findingService.AddFindingAsync(finding, cancellationToken);
                }

                // B5 Düzeltmesi: Olay Merkezi uyarısı tetiklenir (Karantinaya değil, Olay Merkezine yönlendirilir)
                if (_toastService != null)
                {
                    _toastService.ShowToast(
                        "⚠️ Şüpheli Dosya Uyarısı",
                        $"'{fileName}' şüpheli bulundu (Risk Skoru: {finding.RiskScore}/100). Dosyaya dokunulmadı, inceleme için Olay Merkezine kaydedildi.",
                        "Warning");
                }

                if (_auditLogService != null)
                {
                    try
                    {
                        await _auditLogService.LogActionAsync(
                            AuditAction.ScanCompleted,
                            "PolicyEngine",
                            finding.Title,
                            path,
                            $"Şüpheli dosya uyarısı. Risk Skoru: {finding.RiskScore}. Kullanıcı uyarıldı, dosya korundu.",
                            AuditResult.Success,
                            null,
                            cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "Audit log failed for warning");
                    }
                }
            }

            return evaluation;
        }

        private bool CheckSafetyGuardPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;

            if (_protectedPathGuard != null)
            {
                if (_protectedPathGuard.IsProtected(path) || _protectedPathGuard.IsCriticalSystemCore(path))
                {
                    return true;
                }
            }

            if (_reparsePointGuard != null)
            {
                var reparse = _reparsePointGuard.Inspect(path);
                if (reparse.IsReparsePoint)
                {
                    if (reparse.PointsToProtectedTarget ||
                        reparse.IsCrossBoundaryTrap ||
                        (!string.IsNullOrEmpty(reparse.TargetPath) &&
                         (_protectedPathGuard?.IsProtected(reparse.TargetPath) == true ||
                          _protectedPathGuard?.IsCriticalSystemCore(reparse.TargetPath) == true)))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private PolicyEvaluationResult BuildEvaluation(SecurityFinding finding, bool isProtected, bool isMicrosoftSigned)
        {
            if (finding.IsAllowlisted || finding.Status != FindingStatus.Active)
            {
                return new PolicyEvaluationResult
                {
                    Action = PolicyDecisionAction.Allow,
                    Reason = "Bulgu güvenli listede veya daha önce çözümlenmiş.",
                    IsProtectedBySafetyGuard = isProtected,
                    IsMicrosoftSigned = isMicrosoftSigned
                };
            }

            bool enableAutoQuarantine = _settingsService?.GetSetting("EnableAutoQuarantine", true) ?? true;
            int autoQuarantineThreshold = _settingsService?.GetSetting("AutoQuarantineThreshold", 85) ?? 85;
            autoQuarantineThreshold = Math.Clamp(autoQuarantineThreshold, 0, 100);

            bool isConfirmedThreat = finding.Category == FindingCategory.KnownMalwareHash ||
                                     finding.Category == FindingCategory.ConfirmedMalicious;

            if (finding.RiskScore >= autoQuarantineThreshold && isConfirmedThreat)
            {
                if (isProtected)
                {
                    return new PolicyEvaluationResult
                    {
                        Action = PolicyDecisionAction.Warn,
                        Reason = "SafetyGuard Koruması: Kritik Windows veya sistem çekirdek dosyası tespit edildi. Otomatik karantinaya alınamaz, Olay Merkezine yönlendirildi.",
                        IsProtectedBySafetyGuard = true,
                        IsMicrosoftSigned = isMicrosoftSigned
                    };
                }

                if (isMicrosoftSigned)
                {
                    return new PolicyEvaluationResult
                    {
                        Action = PolicyDecisionAction.Warn,
                        Reason = "SafetyGuard Koruması: Geçerli Microsoft dijital imzasına sahip sistem ikilisi tespit edildi. Otomatik karantinaya alınamaz, Olay Merkezine yönlendirildi.",
                        IsProtectedBySafetyGuard = true,
                        IsMicrosoftSigned = true
                    };
                }

                if (!enableAutoQuarantine)
                {
                    return new PolicyEvaluationResult
                    {
                        Action = PolicyDecisionAction.Warn,
                        Reason = "Otomatik karantina kullanıcı ayarlarında devre dışı bırakılmış. Olay Merkezine yönlendirildi.",
                        IsProtectedBySafetyGuard = false,
                        IsMicrosoftSigned = isMicrosoftSigned
                    };
                }

                return new PolicyEvaluationResult
                {
                    Action = PolicyDecisionAction.AutoQuarantine,
                    Reason = $"Kritik zararlı tehdit tespit edildi (Risk: {finding.RiskScore}/100, Kategori: {finding.Category}). Otomatik karantinaya alınıyor.",
                    IsProtectedBySafetyGuard = false,
                    IsMicrosoftSigned = false
                };
            }

            if (finding.RiskScore >= 60)
            {
                return new PolicyEvaluationResult
                {
                    Action = PolicyDecisionAction.Warn,
                    Reason = $"Şüpheli dosya veya davranış tespit edildi (Risk: {finding.RiskScore}/100). Dosyaya dokunulmadı, Olay Merkezine kaydedildi.",
                    IsProtectedBySafetyGuard = isProtected,
                    IsMicrosoftSigned = isMicrosoftSigned
                };
            }

            return new PolicyEvaluationResult
            {
                Action = PolicyDecisionAction.Allow,
                Reason = $"Risk skoru güvenli seviyede ({finding.RiskScore}/100). İşleme izin verildi.",
                IsProtectedBySafetyGuard = isProtected,
                IsMicrosoftSigned = isMicrosoftSigned
            };
        }
    }
}
