using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>
/// Reads local persistence configuration and process image locations without modifying the system.
/// This is an Ultron configuration inspector, not Microsoft MRT or a process-memory scanner.
/// </summary>
public static class SystemPersistenceInspector
{
    private const int MaximumTaskFiles = 1024;
    private const long MaximumConfigurationBytes = 1024 * 1024;
    private static readonly HashSet<string> SecurityDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft.com", "windowsupdate.com", "virustotal.com", "kaspersky.com", "bitdefender.com", "malwarebytes.com"
    };

    /// <summary>
    /// Collects bounded read-only observations and returns heuristic or unknown findings. No finding from
    /// configuration alone is confirmed malware; unreadable sources remain explicit and cancellation propagates.
    /// </summary>
    public static Task<List<SecurityFinding>> ScanAsync(IProgress<string>? phaseReporter = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.Run(() =>
        {
            phaseReporter?.Report("Sistem İncelemesi: Başlangıç ve kayıt defteri yapılandırması okunuyor...");
            var observations = SystemPersistenceRegistryReader.Read(cancellationToken);
            phaseReporter?.Report("Sistem İncelemesi: Hosts yönlendirmeleri inceleniyor...");
            ReadHosts(observations, cancellationToken);
            phaseReporter?.Report("Sistem İncelemesi: Zamanlanmış görev komutları inceleniyor...");
            ReadTasks(observations, cancellationToken);
            phaseReporter?.Report("Sistem İncelemesi: Süreç dosya konumları gözden geçiriliyor...");
            ReadProcesses(observations, cancellationToken);
            var findings = new List<SecurityFinding>();
            foreach (var observation in observations)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var finding = SystemPersistenceEvidenceClassifier.Evaluate(observation);
                if (finding != null) findings.Add(finding);
            }
            return findings;
        }, cancellationToken);
    }

    /// <summary>Reads autorun targets that currently exist without executing them or modifying persistence.</summary>
    public static List<string> GetPersistenceTargetPaths()
    {
        var observations = new List<SystemPersistenceObservation>();
        SystemPersistenceRegistryReader.ReadAutoruns(observations, CancellationToken.None);
        return observations.Where(o => o.Kind == SystemPersistenceObservationKind.Autorun)
            .Select(o => AegisPC.Core.Helpers.PathHelper.ExtractExecutablePath(Environment.ExpandEnvironmentVariables(o.Value)))
            .Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static void ReadHosts(List<SystemPersistenceObservation> observations, CancellationToken cancellationToken)
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
        if (!File.Exists(path)) return;
        try
        {
            using var stream = OpenBounded(path);
            using var reader = new StreamReader(stream);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string content = line.Split('#', 2)[0];
                var parts = content.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2 || !IPAddress.TryParse(parts[0], out var address) ||
                    (!IPAddress.IsLoopback(address) && !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any))) continue;
                foreach (var domain in parts.Skip(1).Where(d => SecurityDomains.Contains(d.TrimEnd('.'))))
                    observations.Add(new SystemPersistenceObservation
                    {
                        Kind = SystemPersistenceObservationKind.SecurityDomainRedirect,
                        ObjectPath = path, ObjectName = "hosts", Value = parts[0] + " " + domain
                    });
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { AddCoverageGap(observations, path, ex.Message); }
    }

    private static void ReadTasks(List<SystemPersistenceObservation> observations, CancellationToken cancellationToken)
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
        if (!Directory.Exists(root)) return;
        try
        {
            int inspected = 0;
            foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (inspected++ >= MaximumTaskFiles)
                { AddCoverageGap(observations, root, "Scheduled task inspection quota exceeded."); break; }
                try
                {
                    using var stream = OpenBounded(path);
                    using var reader = XmlReader.Create(stream, new XmlReaderSettings
                    {
                        DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
                        MaxCharactersInDocument = MaximumConfigurationBytes
                    });
                    var document = XDocument.Load(reader);
                    foreach (var execution in document.Descendants().Where(e => e.Name.LocalName == "Exec"))
                    {
                        string command = string.Join(" ", execution.Elements()
                            .Where(e => e.Name.LocalName is "Command" or "Arguments").Select(e => e.Value));
                        observations.Add(new SystemPersistenceObservation
                        {
                            Kind = SystemPersistenceObservationKind.ScheduledCommand,
                            ObjectPath = path, ObjectName = Path.GetFileName(path), Value = command
                        });
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or XmlException)
                { AddCoverageGap(observations, path, ex.Message); }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { AddCoverageGap(observations, root, ex.Message); }
    }

    private static void ReadProcesses(List<SystemPersistenceObservation> observations, CancellationToken cancellationToken)
    {
        Process[] processes;
        try { processes = Process.GetProcesses(); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        { AddCoverageGap(observations, "Process observation", ex.Message); return; }
        int inaccessible = 0;
        try
        {
            foreach (var process in processes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (process.Id <= 4 || process.Id == Environment.ProcessId) continue;
                    string path = process.MainModule?.FileName ?? string.Empty;
                    if (path.Length == 0) { inaccessible++; continue; }
                    observations.Add(new SystemPersistenceObservation
                    {
                        Kind = SystemPersistenceObservationKind.TemporaryProcess, ObjectPath = path,
                        ObjectName = process.ProcessName, Value = path, ProcessId = process.Id
                    });
                }
                catch (InvalidOperationException ex)
                { Trace.TraceInformation("A process exited before its image could be observed: {0}", ex.Message); }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or NotSupportedException)
                { inaccessible++; Trace.TraceInformation("A process image could not be observed: {0}", ex.Message); }
            }
        }
        finally { foreach (var process in processes) process.Dispose(); }
        if (inaccessible > 0) AddCoverageGap(observations, "Process observation", $"{inaccessible} process images were inaccessible.");
    }

    private static FileStream OpenBounded(string path)
    {
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        if (stream.Length <= MaximumConfigurationBytes) return stream;
        stream.Dispose();
        throw new IOException("Configuration document exceeds the inspection byte limit.");
    }

    private static void AddCoverageGap(List<SystemPersistenceObservation> observations, string source, string reason)
    {
        Trace.TraceWarning("Persistence inspection coverage is incomplete: {0}: {1}", source, reason);
        observations.Add(new SystemPersistenceObservation
        { Kind = SystemPersistenceObservationKind.CoverageGap, ObjectPath = source, ObjectName = "Coverage", Value = reason });
    }
}
