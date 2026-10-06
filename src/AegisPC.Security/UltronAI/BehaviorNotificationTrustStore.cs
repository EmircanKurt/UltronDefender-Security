namespace AegisPC.Security.UltronAI;

/// <summary>Reduces similar behavioral notifications for the same content hash for 24 hours; never suppresses verified malware.</summary>
public sealed class BehaviorNotificationTrustStore
{
    private readonly Dictionary<(string Sid, string Hash, string Family), DateTimeOffset> _entries = new();
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    /// <summary>Creates an in-memory bounded preference store, separate from allowlists and security evidence.</summary>
    public BehaviorNotificationTrustStore(TimeProvider? time = null) => _time = time ?? TimeProvider.System;
    /// <summary>Records a hash-bound preference; missing or malformed hashes cannot create a path exemption.</summary>
    public bool TrustFor24Hours(string ownerSid, string hash, string family)
    {
        if (!Valid(ownerSid, hash, family)) return false;
        lock (_gate)
        {
            foreach (var expiredKey in _entries.Where(x => x.Value <= _time.GetUtcNow()).Select(x => x.Key).ToArray()) _entries.Remove(expiredKey);
            var key = (ownerSid, hash.ToUpperInvariant(), family);
            if (_entries.Count >= 1024 && !_entries.ContainsKey(key)) return false;
            _entries[key] = _time.GetUtcNow().AddHours(24);
            return true;
        }
    }
    /// <summary>Authoritative positive content always bypasses the preference, regardless of signature, path or hash trust.</summary>
    public bool ReduceSimilarNotification(string ownerSid, string hash, string family, bool confirmedContent)
    {
        if (confirmedContent || !Valid(ownerSid, hash, family)) return false;
        lock (_gate) return _entries.TryGetValue((ownerSid, hash.ToUpperInvariant(), family), out var until) && until > _time.GetUtcNow();
    }
    private static bool Valid(string sid, string hash, string family) => !string.IsNullOrWhiteSpace(sid) &&
        hash is { Length: 64 } && hash.All(Uri.IsHexDigit) && !string.IsNullOrWhiteSpace(family) && family.Length <= 128;
}
