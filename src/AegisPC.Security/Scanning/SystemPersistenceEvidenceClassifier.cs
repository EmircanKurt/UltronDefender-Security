using System;
using System.Collections.Generic;
using System.IO;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>Describes the configuration source of a persistence observation, never a malware verdict.</summary>
public enum SystemPersistenceObservationKind
{
    /// <summary>An IFEO debugger redirect was read.</summary>
    DebuggerRedirect,
    /// <summary>The configured desktop shell was read.</summary>
    DesktopShell,
    /// <summary>The configured logon initializer was read.</summary>
    LogonInitializer,
    /// <summary>A global AppInit library configuration was read.</summary>
    GlobalLibraryLoad,
    /// <summary>An autorun command was read.</summary>
    Autorun,
    /// <summary>A service library target was read.</summary>
    ServiceLibrary,
    /// <summary>A scheduled task command was read.</summary>
    ScheduledCommand,
    /// <summary>A hosts entry redirected a security-related domain.</summary>
    SecurityDomainRedirect,
    /// <summary>A process image path was read, without executing or changing the process.</summary>
    TemporaryProcess,
    /// <summary>The inspector could not read part of a configuration source.</summary>
    CoverageGap
}

/// <summary>A read-only snapshot that can be classified without accessing registry, processes, or files.</summary>
public sealed class SystemPersistenceObservation
{
    /// <summary>Identifies the configuration source and determines which review checks apply.</summary>
    public SystemPersistenceObservationKind Kind { get; init; }
    /// <summary>Identifies the observed registry value, task, or image for display; it is never an action target.</summary>
    public string ObjectPath { get; init; } = string.Empty;
    /// <summary>Provides the display label of the observed object, without granting trust.</summary>
    public string ObjectName { get; init; } = string.Empty;
    /// <summary>Contains the observed configuration text; hints in this text cannot establish malware certainty.</summary>
    public string Value { get; init; } = string.Empty;
    /// <summary>Identifies an observed process only for display; the classifier cannot terminate processes.</summary>
    public int? ProcessId { get; init; }
}

/// <summary>
/// Classifies persistence snapshots as review hints. Paths, command text, and configuration changes
/// cannot produce ConfirmedMalicious; exact content signatures must come from the file detection pipeline.
/// </summary>
public static class SystemPersistenceEvidenceClassifier
{
    /// <summary>Returns a bounded review finding, an unknown coverage finding, or null when no review hint is present.</summary>
    public static SecurityFinding? Evaluate(SystemPersistenceObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (string.IsNullOrWhiteSpace(observation.Value)) return null;
        var kind = observation.Kind;
        bool observed = kind switch
        {
            SystemPersistenceObservationKind.DesktopShell => !IsDefaultShell(observation.Value),
            SystemPersistenceObservationKind.LogonInitializer => !IsDefaultLogonInitializer(observation.Value),
            SystemPersistenceObservationKind.ServiceLibrary => HasUserWritableLocationHint(observation.Value),
            SystemPersistenceObservationKind.Autorun => HasCommandReviewHint(observation.Value) ||
                HasTemporaryLocationHint(observation.Value),
            SystemPersistenceObservationKind.ScheduledCommand => HasCommandReviewHint(observation.Value),
            SystemPersistenceObservationKind.TemporaryProcess => HasTemporaryLocationHint(observation.Value),
            _ => true
        };
        if (!observed) return null;

        bool incomplete = kind == SystemPersistenceObservationKind.CoverageGap;
        var (title, score, category) = GetReviewPolicy(kind);
        return new SecurityFinding
        {
            ObjectPath = observation.ObjectPath,
            ObjectName = observation.ObjectName,
            RiskLevel = incomplete ? RiskLevel.Unknown : score >= 50 ? RiskLevel.Suspicious : RiskLevel.LowRisk,
            RiskScore = score,
            Category = category,
            Title = title,
            Description = incomplete
                ? "Bu sistem kaynağı incelenemedi; temiz olduğu sonucuna varılmadı."
                : "Yapılandırma veya konum inceleme sinyali bulundu; zararlı yazılım olarak doğrulanmadı.",
            RiskReasons = new List<string>
            {
                $"Kaynak: {kind}", $"Gözlem: {observation.Value}",
                incomplete ? "İnceleme kapsamı eksik." : "Yalnız bu gözlem otomatik karantina veya süreç sonlandırma gerekçesi değildir."
            },
            ConfidenceLevel = incomplete ? ConfidenceLevel.Low : ConfidenceLevel.Medium,
            Status = FindingStatus.Active
        };
    }

    private static (string Title, int Score, FindingCategory Category) GetReviewPolicy(SystemPersistenceObservationKind kind) =>
        kind switch
        {
            SystemPersistenceObservationKind.DebuggerRedirect => ("Sistem İncelemesi: IFEO hata ayıklayıcı yönlendirmesi", 60, FindingCategory.SuspiciousPersistence),
            SystemPersistenceObservationKind.DesktopShell => ("Sistem İncelemesi: Özel masaüstü kabuğu", 35, FindingCategory.SuspiciousPersistence),
            SystemPersistenceObservationKind.LogonInitializer => ("Sistem İncelemesi: Ek oturum başlatıcısı", 50, FindingCategory.SuspiciousPersistence),
            SystemPersistenceObservationKind.GlobalLibraryLoad => ("Sistem İncelemesi: Global DLL yükleme yapılandırması", 35, FindingCategory.SystemModification),
            SystemPersistenceObservationKind.ServiceLibrary => ("Sistem İncelemesi: Servis DLL konumu", 50, FindingCategory.SuspiciousLocation),
            SystemPersistenceObservationKind.ScheduledCommand => ("Sistem İncelemesi: Görev komutu gözden geçirilmeli", 60, FindingCategory.SuspiciousPersistence),
            SystemPersistenceObservationKind.SecurityDomainRedirect => ("Sistem İncelemesi: Güvenlik alan adı yönlendirmesi", 60, FindingCategory.SystemModification),
            SystemPersistenceObservationKind.TemporaryProcess => ("Sistem İncelemesi: Geçici dizinden çalışan süreç", 60, FindingCategory.MalwareSuspicion),
            SystemPersistenceObservationKind.CoverageGap => ("Sistem İncelemesi: Eksik kapsam", 0, FindingCategory.SystemModification),
            _ => ("Sistem İncelemesi: Başlangıç komutu gözden geçirilmeli", 60, FindingCategory.SuspiciousPersistence)
        };

    private static bool IsDefaultShell(string value) => value.Trim().Trim('"').Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) ||
        value.Trim().Trim('"').Equals(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), StringComparison.OrdinalIgnoreCase);

    private static bool IsDefaultLogonInitializer(string value)
    {
        string expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "userinit.exe");
        var entries = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return entries.Length == 1 &&
            (entries[0].Trim('"').Equals(expected, StringComparison.OrdinalIgnoreCase) ||
             entries[0].Trim('"').Equals("userinit.exe", StringComparison.OrdinalIgnoreCase));
    }

    private static bool HasCommandReviewHint(string value)
    {
        string lower = value.ToLowerInvariant();
        return lower.Contains("-enc ", StringComparison.Ordinal) || lower.Contains("-encodedcommand ", StringComparison.Ordinal) ||
            lower.Contains("-w hidden", StringComparison.Ordinal) || lower.Contains("downloadstring", StringComparison.Ordinal) ||
            lower.Contains("iex(", StringComparison.Ordinal) || lower.Contains("bypass -w hidden", StringComparison.Ordinal);
    }

    private static bool HasTemporaryLocationHint(string value) => value.Contains(@"\temp\", StringComparison.OrdinalIgnoreCase);

    private static bool HasUserWritableLocationHint(string value) => HasTemporaryLocationHint(value) ||
        value.Contains(@"\appdata\", StringComparison.OrdinalIgnoreCase) || value.Contains(@"\downloads\", StringComparison.OrdinalIgnoreCase);
}
