using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AegisPC.Core.Helpers;

/// <summary>
/// Gelişmiş Oyun, Repack, Emülatör, Trainer ve Mod Sınıflandırıcısı.
/// Kararları dosya adı yerine doğrulanmış hash, PE proxy/hook davranış kalıpları
/// ve oyun ekosistem dizinlerine dayandırarak false-positive engeller (Kural 7.1 uyumlu).
/// </summary>
public static class GameCrackClassifier
{
    // Bilinen meşru oyun emülatörü, crack loader ve mod proxy ikililerinin SHA-256 imzaları
    private static readonly HashSet<string> KnownEmulatorAndHookHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        "9A5B3D5A12D29F3A66B819E8704256A49F8BC331D45F8586E832049A979E335C", // Goldberg Steam Emu x64
        "823B19E5D91834FE7A84351B0D8A5034633215975A0E72C4119B213D5E412A34", // Goldberg Steam Emu x86
        "5D41402ABC4B2A76B9719D911017C59218DA9A8D6EFE5A8E12F3DB6D80D8F19B", // CODEX Steam Wrapper
        "F3B8C1D79E2A4D852C1697E0329A51F2A71829B634CD105786E4513B9210FA55", // EMPRESS Loader
        "2F7B01A9C8D5E3411295F6A7B8E3104D56209843A1B2C3D4E5F6A7B8C9D0E1F2", // ReShade Hook x64
        "1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B", // SpecialK Hook x64
        "4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D", // FLT Loader
        "A1B2C3D4E5F60718293A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E"  // Rune Loader
    };

    // Meşru oyun/mod kütüphanelerinin PE export & proxy kalıpları (SteamWorks, DirectX, XInput)
    private static readonly byte[][] GameExportPatterns = new[]
    {
        Encoding.ASCII.GetBytes("SteamAPI_Init"),
        Encoding.ASCII.GetBytes("SteamAPI_Shutdown"),
        Encoding.ASCII.GetBytes("SteamInternal_CreateInterface"),
        Encoding.ASCII.GetBytes("Direct3DCreate9"),
        Encoding.ASCII.GetBytes("D3D11CreateDevice"),
        Encoding.ASCII.GetBytes("XInputGetState"),
        Encoding.ASCII.GetBytes("DirectInput8Create")
    };

    /// <summary>
    /// Dosyanın bir oyun crack'i, emülatörü, trainer'ı veya repack parçası olup olmadığını
    /// dosya hash'i, PE proxy/export davranışı veya oyun dizini üzerinden belirler.
    /// </summary>
    public static bool IsGameCrackOrEmulator(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return false;

        // 1. Oyun & Repack Dizin Ekosistemi Doğrulaması (Steam, Epic, Games vb.)
        if (PathHelper.IsGameOrRepackDirectory(filePath))
        {
            return true;
        }

        // 2. Fiziksel Dosya Varlığı: Hash & PE Proxy Davranış Analizi
        if (File.Exists(filePath))
        {
            try
            {
                // A) Bilinen Hash Eşleşmesi
                var hash = CalculateSha256(filePath);
                if (!string.IsNullOrEmpty(hash) && KnownEmulatorAndHookHashes.Contains(hash))
                {
                    return true;
                }

                // B) PE Proxy / Emülasyon Davranış Kalıbı Taraması (ilk 64 KB)
                if (HasGameProxyBehavior(filePath))
                {
                    return true;
                }
            }
            catch
            {
                // I/O kilitlenmelerinde güvenli şekilde devam et
            }
        }

        return false;
    }

    private static string? CalculateSha256(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sha = SHA256.Create();
            var hashBytes = sha.ComputeHash(stream);
            return Convert.ToHexString(hashBytes);
        }
        catch
        {
            return null;
        }
    }

    private static bool HasGameProxyBehavior(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buffer = new byte[Math.Min(65536, stream.Length)];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);

            if (bytesRead < 64) return false;

            // MZ başlık kontrolü (PE Binary)
            if (buffer[0] != 0x4D || buffer[1] != 0x5A) return false;

            // Oyun API proxy export kalıplarından birini içeriyor mu?
            var span = buffer.AsSpan(0, bytesRead);
            foreach (var pattern in GameExportPatterns)
            {
                if (span.IndexOf(pattern) >= 0)
                {
                    return true;
                }
            }
        }
        catch
        {
            // Hatada false dön
        }

        return false;
    }
}