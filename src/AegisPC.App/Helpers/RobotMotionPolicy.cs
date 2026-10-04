using System;
using System.Windows;

namespace AegisPC.App.Helpers;

/// <summary>
/// Defines bounded, side-effect-free robot movement and lifecycle decisions.
/// Coordinates are device-independent pixels; the policy never reads global input.
/// </summary>
public static class RobotMotionPolicy
{
    /// <summary>Gets the largest permitted eye translation in device-independent pixels.</summary>
    public const double MaximumGazeOffset = 2.5;

    /// <summary>Gets the minimum interval between visual updates, limiting motion to fewer than thirty updates per second.</summary>
    public static TimeSpan UpdateInterval => TimeSpan.FromMilliseconds(34);

    /// <summary>Allows input tracking only for a loaded, visible control in an active, visible, non-minimized window.</summary>
    public static bool CanTrackPointer(bool isLoaded, bool isVisible, bool isWindowVisible,
        bool isWindowActive, bool isMinimized, bool motionAllowed) =>
        isLoaded && isVisible && isWindowVisible && isWindowActive && !isMinimized && motionAllowed;

    /// <summary>
    /// Converts a local pointer position into a bounded gaze around the control centre.
    /// Non-finite input returns the neutral gaze rather than assigning invalid WPF coordinates.
    /// </summary>
    public static Point CalculateGaze(Point pointer, Point centre)
    {
        if (!double.IsFinite(pointer.X) || !double.IsFinite(pointer.Y) ||
            !double.IsFinite(centre.X) || !double.IsFinite(centre.Y))
            return new Point();

        return new Point(
            Math.Clamp((pointer.X - centre.X) / 140, -1, 1) * MaximumGazeOffset,
            Math.Clamp((pointer.Y - centre.Y) / 140, -1, 1) * MaximumGazeOffset);
    }

    /// <summary>Approaches a finite target and snaps at the settling threshold so no idle update loop remains.</summary>
    public static double Approach(double current, double target)
    {
        if (!double.IsFinite(current) || !double.IsFinite(target)) return 0;
        double distance = target - current;
        return Math.Abs(distance) <= 0.02 ? target : current + distance * 0.35;
    }
}
