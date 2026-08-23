using System;
using System.Collections.Generic;
using System.IO;

namespace AegisPC.Core.Helpers;

/// <summary>
/// Gelişmiş Oyun, Repack, Emülatör, Trainer ve Crack Sınıflandırıcısı.
/// Meşru oyun hileleri, modlar, Steam/Epic emülatörleri ve aktivasyon araçlarının
/// yanlış pozitif (False Positive) olarak karantinaya alınmasını önler.
/// </summary>
public static class GameCrackClassifier
{
    private static readonly HashSet<string> KnownEmulatorAndHookFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        // Steam Emulators & Hook DLLs
        "steam_api.dll", "steam_api64.dll", "steamclient.dll", "steamclient64.dll",
        "steamwebrtc.dll", "steamwebrtc64.dll", "goldberg.dll", "goldberg64.dll",
        "mr_goldberg.dll", "steam_emu.ini", "steam_interfaces.txt", "steam_appid.txt",
        "local_save.txt", "SmartSteamEmu.dll", "SmartSteamEmu64.dll", "SteamOverlay64.dll",
        "CreamAPI.dll", "CreamAPI64.dll", "GreenLuma.dll", "GreenLuma64.dll", "SmokeAPI.dll",
        "Koaloader.dll", "Koaloader32.dll", "Koaloader64.dll",

        // Scene Groups & Crack Loaders
        "rld.dll", "rldea.dll", "codex.dll", "codex64.dll", "emp.dll", "emp64.dll",
        "galaxy.dll", "galaxy64.dll", "uplay_r1_loader.dll", "uplay_r1_loader64.dll",
        "EOSSDK-Win64-Shipping.dll", "EOSSDK-Win32-Shipping.dll", "anadius64.dll", "anadius32.dll",
        "3dmgame.dll", "3dmgame64.dll", "OnlineFix64.dll", "OnlineFix.dll", "OnlineFix.ini",
        "Rune.dll", "FLT.dll", "Tenoke.dll", "Razor1911.dll", "SKIDROW.dll", "CPY.dll",
        "PLAZA.dll", "Reloaded.dll", "ALI213.dll", "CHRONOS.dll", "Fairlight.dll",

        // Proxy, Graphics & Mod Hooking DLLs (ReShade, SpecialK, DLSS Mods)
        "dxgi.dll", "d3d11.dll", "d3d9.dll", "d3d12.dll", "dinput8.dll", "xinput1_3.dll",
        "xinput1_4.dll", "xinput9_1_0.dll", "version.dll", "winmm.dll", "winhttp.dll",
        "dbghelp.dll", "binkw32.dll", "binkw64.dll", "bink2w64.dll", "bink2w32.dll",
        "UnityPlayer.dll", "ReShade32.dll", "ReShade64.dll", "SpecialK32.dll", "SpecialK64.dll",
        "OptiScaler.dll", "nvngx.dll", "sl.interposer.dll",

        // Trainer & Cheat Engine Components
        "cheatengine-x86_64.exe", "cheatengine-i386.exe", "Wemod.exe", "WemodAuxiliaryService.exe",
        "FlingTrainer.exe", "FlingTrainer64.exe", "MrAntiFun.exe", "Plitch.exe", "Aurora.exe",

        // Open-Source Activation Scripts & Utilities
        "MAS_AIO.cmd", "MAS_AIO.ps1", "KMS_VL_ALL.cmd", "Activate.cmd"
    };

    private static readonly string[] KnownRepackAndGameDirectories = new[]
    {
        // Scene Groups & Repackers
        "_crack", "crack", "nocd", "razor1911", "codex", "plaza", "cpy", "flt", "skidrow",
        "insaneramzes", "fitgirl", "dodi", "elamigos", "kaos", "tinyiso", "rune", "tenoke",
        "goldberg", "empress", "reloaded", "onlinefix", "steamrip", "steamunlocked", "igg-games",
        "gamedrive", "byxatab", "chovka", "repack", "fairlight",

        // Game Launchers & Platforms
        "steamapps", "common", "steamlibrary", "epic games", "riot games", "ubisoft", "rockstar games",
        "gog games", "gog galaxy", "ea games", "origin games", "battle.net", "xboxgames",
        @"\games\", @"\oyunlar\", @"\oyun\", @"\games library\", "modorganizer", "vortex", "curseforge",

        // Popular Game Titles / Engines
        "beamng", "minecraft", ".minecraft", "roblox", "unity", "unreal", "gta5", "gtav",
        "cyberpunk", "witcher", "elden ring", "red dead redemption", "fifa", "pes", "forza"
    };

    private static readonly string[] KnownTrainerKeywordPrefixes = new[]
    {
        "trainer", "fling", "mrantifun", "wemod", "cheatengine", "cheathappens", "modengine"
    };

    /// <summary>
    /// Dosyanın bir oyun crack'i, emülatörü, trainer'ı veya repack parçası olup olmadığını belirler.
    /// </summary>
    public static bool IsGameCrackOrEmulator(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return false;

        var fileName = Path.GetFileName(filePath);
        if (KnownEmulatorAndHookFiles.Contains(fileName)) return true;

        var fileNameLower = fileName.ToLowerInvariant();
        foreach (var prefix in KnownTrainerKeywordPrefixes)
        {
            if (fileNameLower.Contains(prefix)) return true;
        }

        var normalized = filePath.ToLowerInvariant();
        foreach (var dir in KnownRepackAndGameDirectories)
        {
            if (normalized.Contains(dir, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}