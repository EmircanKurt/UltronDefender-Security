using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Security;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.SelfDefense
{
    public record ProcessCreationEvent
    {
        public int ProcessId { get; init; }
        public int ParentProcessId { get; init; }
        public string ImagePath { get; init; } = string.Empty;
        public string CommandLine { get; init; } = string.Empty;
        public string ParentImagePath { get; init; } = string.Empty;
        public string User { get; init; } = string.Empty;
        public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;
        public string SourceLog { get; init; } = "Unknown";
    }

    /// <summary>
    /// Windows Olay Günlüğü Okuyucusu ve Canlı İzleyicisi (Sysmon Event ID 1 + Security Event ID 4688).
    /// Sistemde oluşturulan tüm süreçleri gerçek zamanlı izleyerek Anti-Tamper motoruna telemetri besler.
    /// </summary>
    public class EventLogReader : IDisposable
    {
        private readonly ILogger<EventLogReader>? _logger;
        private EventLogWatcher? _sysmonWatcher;
        private EventLogWatcher? _securityWatcher;
        private bool _isListening;
        private readonly object _lock = new();

        public bool IsListening => _isListening;
        public bool IsSysmonAvailable { get; private set; }
        public bool IsSecurityLogAvailable { get; private set; }

        public event Action<ProcessCreationEvent>? ProcessCreated;

        public EventLogReader(ILogger<EventLogReader>? logger = null)
        {
            _logger = logger;
        }

        public void StartListening()
        {
            lock (_lock)
            {
                if (_isListening) return;

                // 1. Sysmon Event ID 1 (Process Create) İzleyici
                try
                {
                    var sysmonQuery = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName, "*[System[(EventID=1)]]");
                    _sysmonWatcher = new EventLogWatcher(sysmonQuery);
                    _sysmonWatcher.EventRecordWritten += OnSysmonEventWritten;
                    _sysmonWatcher.Enabled = true;
                    IsSysmonAvailable = true;
                    _logger?.LogInformation("Sysmon Event ID 1 canlı izleme başlatıldı.");
                }
                catch (Exception ex)
                {
                    IsSysmonAvailable = false;
                    _logger?.LogWarning("Sysmon günlüğü açılamadı (Sysmon kurulu olmayabilir): {Message}", ex.Message);
                }

                // 2. Windows Güvenlik Günlüğü Event ID 4688 (A new process has been created)
                try
                {
                    var secQuery = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4688)]]");
                    _securityWatcher = new EventLogWatcher(secQuery);
                    _securityWatcher.EventRecordWritten += OnSecurityEventWritten;
                    _securityWatcher.Enabled = true;
                    IsSecurityLogAvailable = true;
                    _logger?.LogInformation("Windows Güvenlik Günlüğü (Event 4688) canlı izleme başlatıldı.");
                }
                catch (Exception ex)
                {
                    IsSecurityLogAvailable = false;
                    _logger?.LogWarning("Security günlüğü açılamadı (Yönetici yetkisi gereklidir): {Message}", ex.Message);
                }

                _isListening = true;
            }
        }

        public void StopListening()
        {
            lock (_lock)
            {
                if (!_isListening) return;

                try
                {
                    if (_sysmonWatcher != null)
                    {
                        _sysmonWatcher.Enabled = false;
                        _sysmonWatcher.Dispose();
                        _sysmonWatcher = null;
                    }

                    if (_securityWatcher != null)
                    {
                        _securityWatcher.Enabled = false;
                        _securityWatcher.Dispose();
                        _securityWatcher = null;
                    }
                }
                catch { }

                _isListening = false;
            }
        }

        public void FeedSyntheticEvent(ProcessCreationEvent evt)
        {
            if (evt == null) return;
            try
            {
                ProcessCreated?.Invoke(evt);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "FeedSyntheticEvent işlenirken hata oluştu.");
            }
        }

        private void OnSysmonEventWritten(object? sender, EventRecordWrittenEventArgs args)
        {
            if (args.EventRecord == null) return;

            try
            {
                using var record = args.EventRecord;
                string xml = record.ToXml();
                var parsed = ParseSysmonEventXml(xml);
                if (parsed != null)
                {
                    ProcessCreated?.Invoke(parsed);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Sysmon Event ID 1 parse edilirken hata oluştu.");
            }
        }

        private void OnSecurityEventWritten(object? sender, EventRecordWrittenEventArgs args)
        {
            if (args.EventRecord == null) return;

            try
            {
                using var record = args.EventRecord;
                string xml = record.ToXml();
                var parsed = ParseSecurity4688EventXml(xml);
                if (parsed != null)
                {
                    ProcessCreated?.Invoke(parsed);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Security Event ID 4688 parse edilirken hata oluştu.");
            }
        }

        public static ProcessCreationEvent? ParseSysmonEventXml(string xml)
        {
            if (string.IsNullOrWhiteSpace(xml)) return null;

            try
            {
                var doc = XDocument.Parse(xml);
                XNamespace ns = doc.Root?.GetDefaultNamespace() ?? XNamespace.None;

                var dataDict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var element in doc.Descendants(ns + "Data"))
                {
                    string? name = element.Attribute("Name")?.Value;
                    if (!string.IsNullOrEmpty(name))
                    {
                        dataDict[name] = element.Value;
                    }
                }

                dataDict.TryGetValue("ProcessId", out var pidStr);
                dataDict.TryGetValue("ParentProcessId", out var ppidStr);
                dataDict.TryGetValue("Image", out var image);
                dataDict.TryGetValue("CommandLine", out var cmdLine);
                dataDict.TryGetValue("ParentImage", out var parentImage);
                dataDict.TryGetValue("User", out var user);
                dataDict.TryGetValue("UtcTime", out var timeStr);

                int pid = ParseProcessId(pidStr);
                int ppid = ParseProcessId(ppidStr);
                DateTime timestamp = DateTime.TryParse(timeStr, out var dt) ? dt : DateTime.UtcNow;

                return new ProcessCreationEvent
                {
                    ProcessId = pid,
                    ParentProcessId = ppid,
                    ImagePath = image ?? string.Empty,
                    CommandLine = cmdLine ?? string.Empty,
                    ParentImagePath = parentImage ?? string.Empty,
                    User = user ?? string.Empty,
                    TimestampUtc = timestamp,
                    SourceLog = "Sysmon-Event1"
                };
            }
            catch
            {
                return null;
            }
        }

        public static ProcessCreationEvent? ParseSecurity4688EventXml(string xml)
        {
            if (string.IsNullOrWhiteSpace(xml)) return null;

            try
            {
                var doc = XDocument.Parse(xml);
                XNamespace ns = doc.Root?.GetDefaultNamespace() ?? XNamespace.None;

                var dataDict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var element in doc.Descendants(ns + "Data"))
                {
                    string? name = element.Attribute("Name")?.Value;
                    if (!string.IsNullOrEmpty(name))
                    {
                        dataDict[name] = element.Value;
                    }
                }

                dataDict.TryGetValue("NewProcessId", out var pidStr);
                dataDict.TryGetValue("ProcessId", out var parentPidStr);
                dataDict.TryGetValue("NewProcessName", out var image);
                dataDict.TryGetValue("CommandLine", out var cmdLine);
                dataDict.TryGetValue("ParentProcessName", out var parentImage);
                dataDict.TryGetValue("SubjectUserName", out var user);

                int pid = ParseProcessId(pidStr);
                int ppid = ParseProcessId(parentPidStr);

                return new ProcessCreationEvent
                {
                    ProcessId = pid,
                    ParentProcessId = ppid,
                    ImagePath = image ?? string.Empty,
                    CommandLine = cmdLine ?? string.Empty,
                    ParentImagePath = parentImage ?? string.Empty,
                    User = user ?? string.Empty,
                    TimestampUtc = DateTime.UtcNow,
                    SourceLog = "Security-4688"
                };
            }
            catch
            {
                return null;
            }
        }

        private static int ParseProcessId(string? idStr)
        {
            if (string.IsNullOrWhiteSpace(idStr)) return 0;
            idStr = idStr.Trim();

            // 0x1a4 gibi hex format kontrolü (Security 4688 genelde hex döndürür)
            if (idStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    return Convert.ToInt32(idStr, 16);
                }
                catch { }
            }

            if (int.TryParse(idStr, out int val))
            {
                return val;
            }

            return 0;
        }

        public void Dispose()
        {
            StopListening();
        }
    }
}
