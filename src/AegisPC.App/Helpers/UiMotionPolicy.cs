using System.Windows;
using System.Windows.Media;

namespace AegisPC.App.Helpers;

/// <summary>
/// Applies the Windows animation preference and rendering capability to optional UI motion.
/// It does not alter the preference or enable software rendering effects.
/// </summary>
public static class UiMotionPolicy
{
    /// <summary>Gets whether optional motion is suitable for the current Windows UI environment.</summary>
    public static bool CanAnimate => ShouldAnimate(SystemParameters.ClientAreaAnimation, RenderCapability.Tier >> 16);

    /// <summary>
    /// Allows optional motion only when Windows animations are enabled and hardware rendering is available.
    /// Unknown and lower rendering tiers use the static presentation.
    /// </summary>
    public static bool ShouldAnimate(bool clientAreaAnimation, int renderingTier) =>
        clientAreaAnimation && renderingTier >= 2;
}
