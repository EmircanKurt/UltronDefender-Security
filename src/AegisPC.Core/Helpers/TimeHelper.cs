using System;

namespace AegisPC.Core.Helpers;

public static class TimeHelper
{
    public static string FormatRelativeTime(DateTime time)
    {
        var span = DateTime.UtcNow - time;
        if (span.TotalSeconds < 60) return "Just now";
        if (span.TotalMinutes < 60) return $"{(int)span.TotalMinutes} minutes ago";
        if (span.TotalHours < 24) return $"{(int)span.TotalHours} hours ago";
        return $"{(int)span.TotalDays} days ago";
    }

    public static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalHours >= 1) return $"{(int)duration.TotalHours}h {duration.Minutes}m";
        if (duration.TotalMinutes >= 1) return $"{duration.Minutes}m {duration.Seconds}s";
        return $"{duration.Seconds}s";
    }
}
