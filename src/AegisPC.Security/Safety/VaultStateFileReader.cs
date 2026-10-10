using System.IO;
using System.Security.Cryptography;

namespace AegisPC.Security.Safety;

/// <summary>Reads small legacy key/entropy state with a held read-only identity and an explicit allocation limit.</summary>
internal static class VaultStateFileReader
{
    internal const int MaximumBytes = 8192;

    internal static byte[] Read(string path)
    {
        using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (source.Length > MaximumBytes)
            throw new CryptographicException("LegacyMigrationRequired: vault key or entropy state exceeds the supported 8192-byte budget.");
        byte[] content = new byte[(int)source.Length];
        source.ReadExactly(content);
        if (source.Length != content.Length)
            throw new CryptographicException("Vault key or entropy identity changed while reading; construction stopped.");
        return content;
    }
}
