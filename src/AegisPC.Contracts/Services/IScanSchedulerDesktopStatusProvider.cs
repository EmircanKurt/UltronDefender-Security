namespace AegisPC.Contracts.Services;

/// <summary>Separates observed fullscreen interference from an unavailable interactive-desktop measurement.</summary>
public interface IScanSchedulerDesktopStatusProvider
{
    /// <summary>Returns true for observed interference, false for a measured available desktop, and null when another session cannot be inspected.</summary>
    bool? GetFullscreenOrGameActivity();
}
