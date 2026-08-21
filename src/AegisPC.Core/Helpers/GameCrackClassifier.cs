using System;
using System.Collections.Generic;
using System.IO;

namespace AegisPC.Core.Helpers;

public static class GameCrackClassifier
{
    private static readonly HashSet<string> KnownEmulatorFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam_api.dll", "steam_api64.dll", "steamclient.dll", "steamclient64.dll",
        "steamwebrtc.dll", "steamwebrtc64.dll", "goldberg.dll", "rld.dll", "rldea.dll",
        "codex.dll", "codex64.dll", "emp.dll", "galaxy.dll", "galaxy64.dll",
        "uplay_r1_loader.dll", "uplay_r1_loader64.dll", "EOSSDK-Win64-Shipping.dll",
        "CreamAPI.dll", "GreenLuma.dll", "SmartSteamEmu.dll", "anadius64.dll", "3dmgame.dll"
    };

    private static readonly string[] KnownCrackDirectories = new[]
    {
        @"\_crack", @"/_crack", @"\crack", @"/crack", @"\nocd", @"\razor1911", @"\codex",
        @"\plaza", @"\cpy", @"\flt", @"\skidrow", "-insaneramzes", @"\fitgirl", @"\dodi"
    };

    public static bool IsGameCrackOrEmulator(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return false;

        var fileName = Path.GetFileName(filePath);
        if (KnownEmulatorFiles.Contains(fileName)) return true;

        var normalized = filePath.ToLowerInvariant();
        foreach (var dir in KnownCrackDirectories)
        {
            if (normalized.Contains(dir, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}