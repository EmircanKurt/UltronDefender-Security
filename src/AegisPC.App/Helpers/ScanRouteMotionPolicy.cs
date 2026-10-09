namespace AegisPC.App.Helpers;

/// <summary>Bounds decorative route motion; it never infers inspection phases, clean verdicts or security actions.</summary>
public static class ScanRouteMotionPolicy
{
    /// <summary>Caps UI updates at twenty per second; a complete decorative route takes eight seconds.</summary>
    public static TimeSpan UpdateInterval => TimeSpan.FromMilliseconds(50);
    /// <summary>Stops activity decoration when no observed file/counter update has arrived for fifteen seconds.</summary>
    public const double ActivityAgeLimitSeconds = 15;
    /// <summary>Permits animation only for fresh running scans in a visible, loaded, non-minimized supported UI.</summary>
    public static bool CanAnimate(bool running, bool paused, bool loaded, bool visible, bool ownerVisible,
        bool minimized, bool motionAllowed, double activityAgeSeconds) => running && !paused && loaded && visible &&
        ownerVisible && !minimized && motionAllowed && double.IsFinite(activityAgeSeconds) && activityAgeSeconds >= 0 && activityAgeSeconds < ActivityAgeLimitSeconds;
    /// <summary>Advances the decorative phase with capped elapsed time; invalid inputs return a finite neutral phase.</summary>
    public static double Advance(double phase, double elapsedSeconds) => !double.IsFinite(phase) || !double.IsFinite(elapsedSeconds)
        ? 0 : (Math.Clamp(phase, 0, 1) + Math.Clamp(elapsedSeconds, 0, .25) / 8) % 1;
    /// <summary>Moves files forward with a slow cosine ease; the faded reset is not a real completion percentage.</summary>
    public static double Offset(double phase) => double.IsFinite(phase) ? (1 - Math.Cos(Math.Clamp(phase, 0, 1) * Math.PI)) * 66 : 0;
}
