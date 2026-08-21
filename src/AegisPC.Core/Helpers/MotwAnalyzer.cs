using System;
using System.IO;
using System.Text.RegularExpressions;

namespace AegisPC.Core.Helpers
{
    public enum SecurityZone
    {
        Unknown = -1,
        LocalMachine = 0,
        Intranet = 1,
        Trusted = 2,
        Internet = 3,
        Restricted = 4
    }

    public class MotwInfo
    {
        public bool HasMotw { get; set; }
        public SecurityZone Zone { get; set; } = SecurityZone.LocalMachine;
        public int ZoneId { get; set; } = 0;
        public string? ReferrerUrl { get; set; }
        public string? HostUrl { get; set; }

        public bool IsFromInternet => Zone == SecurityZone.Internet || Zone == SecurityZone.Restricted;
    }

    public static class MotwAnalyzer
    {
        public static MotwInfo ParseZoneIdentifierContent(string content)
        {
            if (string.IsNullOrWhiteSpace(content))
            {
                return new MotwInfo { HasMotw = false, Zone = SecurityZone.LocalMachine, ZoneId = 0 };
            }

            var info = new MotwInfo { HasMotw = true };

            var zoneMatch = Regex.Match(content, @"ZoneId\s*=\s*(\d+)", RegexOptions.IgnoreCase);
            if (zoneMatch.Success && int.TryParse(zoneMatch.Groups[1].Value, out int zoneId))
            {
                info.ZoneId = zoneId;
                info.Zone = zoneId switch
                {
                    0 => SecurityZone.LocalMachine,
                    1 => SecurityZone.Intranet,
                    2 => SecurityZone.Trusted,
                    3 => SecurityZone.Internet,
                    4 => SecurityZone.Restricted,
                    _ => SecurityZone.Unknown
                };
            }

            var hostMatch = Regex.Match(content, @"HostUrl\s*=\s*([^\r\n]+)", RegexOptions.IgnoreCase);
            if (hostMatch.Success)
            {
                info.HostUrl = hostMatch.Groups[1].Value.Trim();
            }

            var refMatch = Regex.Match(content, @"ReferrerUrl\s*=\s*([^\r\n]+)", RegexOptions.IgnoreCase);
            if (refMatch.Success)
            {
                info.ReferrerUrl = refMatch.Groups[1].Value.Trim();
            }

            return info;
        }

        public static MotwInfo GetMotwInfo(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                return new MotwInfo { HasMotw = false, Zone = SecurityZone.LocalMachine, ZoneId = 0 };
            }

            try
            {
                // NTFS Alternate Data Stream for Mark of the Web
                var adsPath = filePath + ":Zone.Identifier";
                if (File.Exists(adsPath))
                {
                    var content = File.ReadAllText(adsPath);
                    return ParseZoneIdentifierContent(content);
                }
            }
            catch
            {
            }

            return new MotwInfo { HasMotw = false, Zone = SecurityZone.LocalMachine, ZoneId = 0 };
        }
    }
}
