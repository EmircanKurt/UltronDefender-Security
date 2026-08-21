using System;

namespace AegisPC.Core.Helpers;

public static class FileSizeHelper
{
    private static readonly string[] SizeSuffixes = { "bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" };

    public static string FormatBytes(long value)
    {
        if (value < 0) return "-" + FormatBytes(-value);
        if (value == 0) return "0 bytes";

        int mag = (int)Math.Log(value, 1024);
        decimal adjustedSize = (decimal)value / (1L << (mag * 10));

        if (Math.Round(adjustedSize, 1) >= 1000)
        {
            mag += 1;
            adjustedSize /= 1024;
        }

        return string.Format("{0:n1} {1}", adjustedSize, SizeSuffixes[mag]);
    }
}
