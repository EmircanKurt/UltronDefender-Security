using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using AegisPC.Contracts.Protection;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Remote;

/// <summary>Inert-until-start Security-log subscriber. It does not enable auditing, modify RDP or block connections.</summary>
public sealed class WindowsRdpLogonObservationSource(ILogger<WindowsRdpLogonObservationSource>? logger = null) : IRdpLogonObservationSource
{
    private const int Capacity = 256;
    private readonly Queue<RdpLogonObservation> _pending = new();
    private readonly object _gate = new();
    private readonly object _lifecycle = new();
    private EventLogWatcher? _watcher;
    private SecurityObservationAvailability _availability;
    private string? _failure;
    private long _lost;
    private bool _disposed;

    /// <inheritdoc />
    public void Start()
    {
        lock (_lifecycle)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_watcher != null) return;
            if (!OperatingSystem.IsWindows()) { SetUnavailable("Security-log observation requires Windows."); return; }
            EventLogWatcher? candidate = null;
            try
            {
                var query = new EventLogQuery("Security", PathType.LogName,
                    "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624 or EventID=4625)]]");
                candidate = new EventLogWatcher(query);
                candidate.EventRecordWritten += OnRecord;
                // Partial is intentional: subscribing cannot prove audit policy completeness or classify every NLA failure.
                lock (_gate) { _availability = SecurityObservationAvailability.Partial; _failure = null; }
                candidate.Enabled = true;
                _watcher = candidate;
            }
            catch (Exception exception) when (exception is EventLogException or UnauthorizedAccessException or InvalidOperationException)
            {
                if (candidate != null) { candidate.EventRecordWritten -= OnRecord; candidate.Dispose(); }
                logger?.LogWarning(exception, "Remote Security-log subscription is unavailable.");
                SetUnavailable("Security-log subscription failed or access was denied; remote event coverage is unavailable.");
            }
        }
    }

    /// <inheritdoc />
    public void Stop()
    {
        lock (_lifecycle)
        {
            var previous = _watcher;
            _watcher = null;
            if (previous != null)
            {
                previous.EventRecordWritten -= OnRecord;
                try { previous.Enabled = false; }
                catch (EventLogException exception) { logger?.LogWarning(exception, "Remote logon subscription stop failed."); }
                finally { previous.Dispose(); }
            }
            SetUnavailable("Remote-logon observation is stopped.");
        }
    }

    /// <inheritdoc />
    public RdpLogonBatch Drain(DateTime utcNow)
    {
        lock (_gate)
        {
            var events = _pending.ToArray();
            _pending.Clear();
            var limitations = new List<string>
            {
                "Post-logon Security events are observations, not pre-connection approval hooks.",
                "Audit policy has not been enabled or verified by Ultron; missing events remain possible.",
                "Only structured RemoteInteractive logons identify RDP; NLA Network-logon failures are not classified as RDP."
            };
            if (_failure != null) limitations.Add(_failure);
            if (_lost != 0) limitations.Add("Remote-logon managed queue dropped records; event history is incomplete.");
            return new() { CapturedAtUtc = utcNow, Availability = _availability, Events = events,
                LostEvents = _lost, Limitations = limitations.ToArray() };
        }
    }

    private void OnRecord(object? sender, EventRecordWrittenEventArgs args)
    {
        if (args.EventException != null)
        {
            logger?.LogWarning(args.EventException, "Remote-logon event source reported a failure.");
            SetUnavailable("Security-log event delivery failed; remote event coverage is incomplete.");
        }
        using var record = args.EventRecord;
        if (record == null) return;
        try
        {
            var parsed = ParseSecurityEventXml(record.ToXml());
            if (parsed == null) return;
            lock (_gate)
            {
                if (_availability is SecurityObservationAvailability.Unavailable or SecurityObservationAvailability.Pending) return;
                if (_pending.Count == Capacity) { _lost++; return; }
                _pending.Enqueue(parsed);
            }
        }
        catch (Exception exception) when (exception is EventLogException or XmlException or ArgumentException or InvalidOperationException)
        {
            logger?.LogWarning(exception, "Remote-logon event metadata could not be parsed.");
            lock (_gate) { _lost++; _failure = "A Security-log event could not be interpreted; coverage is incomplete."; }
        }
    }

    /// <summary>Parses bounded, DTD-free structured Security event XML without accessing Windows logs or executing event content.</summary>
    public static RdpLogonObservation? ParseSecurityEventXml(string xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        if (xml.Length > 65536) return null;
        using var input = new StringReader(xml);
        using var reader = XmlReader.Create(input, new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 65536 });
        var document = XDocument.Load(reader);
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        var system = document.Root?.Element(ns + "System");
        if (system?.Element(ns + "Provider")?.Attribute("Name")?.Value != "Microsoft-Windows-Security-Auditing") return null;
        if (!int.TryParse(system.Element(ns + "EventID")?.Value, out int id) || id is not (4624 or 4625)) return null;
        if (!DateTime.TryParse(system.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value,
            CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var time) || time.Kind == DateTimeKind.Unspecified) return null;
        var values = document.Root?.Element(ns + "EventData")?.Elements(ns + "Data").Take(64).ToArray() ?? [];
        string Read(string name) => values.FirstOrDefault(element => element.Attribute("Name")?.Value == name)?.Value ?? string.Empty;
        if (!int.TryParse(Read("LogonType"), out int logonType) || logonType is not (3 or 10)) return null;
        string recordId = system.Element(ns + "EventRecordID")?.Value ?? string.Empty;
        if (recordId.Length > 32 || !ulong.TryParse(recordId, out _)) return null;
        string address = Read("IpAddress"), sid = Read("TargetUserSid");
        if (address.Length > 64 || sid.Length > 256) return null;
        // Unresolved/null SID is not an invented account identity.
        if (!sid.StartsWith("S-1-", StringComparison.Ordinal) || sid == "S-1-0-0") sid = string.Empty;
        return new()
        {
            EventIdentity = $"Security/{recordId}/{time.ToUniversalTime():O}/{id}", TimestampUtc = time.ToUniversalTime(),
            RemoteAddress = address, TargetSid = sid, IsAuthenticationFailure = id == 4625, IsRdpCorrelated = logonType == 10
        };
    }

    private void SetUnavailable(string reason)
    { lock (_gate) { _availability = SecurityObservationAvailability.Unavailable; _failure = reason; } }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_lifecycle)
        {
            if (_disposed) return;
            Stop();
            _disposed = true;
        }
    }
}
