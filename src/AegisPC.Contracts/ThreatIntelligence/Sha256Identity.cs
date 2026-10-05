namespace AegisPC.Contracts.ThreatIntelligence;

/// <summary>Strict ASCII SHA-256 syntax shared by import and detection. Does not validate provenance.</summary>
public static class Sha256Identity
{
    public static bool IsValid(string? value)
    {
        if (value is not { Length: 64 }) return false;
        foreach (char c in value)
            if (!(c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F')) return false;
        return true;
    }
}

