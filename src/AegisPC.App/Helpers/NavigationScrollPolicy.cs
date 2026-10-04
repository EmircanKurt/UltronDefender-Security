using System;
using System.Windows;
using System.Windows.Controls;
using Wpf.Ui.Controls;

namespace AegisPC.App.Helpers;

/// <summary>
/// Gives each application page ownership of its viewport instead of wrapping its
/// ScrollViewer or virtualized grid in the navigation library's scrolling surface.
/// This does not change item-control virtualization or install any input hooks.
/// </summary>
public static class NavigationScrollPolicy
{
    /// <summary>
    /// Disables the navigation presenter's extra scrolling layer for an application
    /// page that owns its scrolling layout. The presenter may be absent before its
    /// template exists; the page value still governs subsequent navigation.
    /// </summary>
    public static void ConfigurePageOwnedScrolling(DependencyObject page, NavigationViewContentPresenter? presenter)
    {
        ArgumentNullException.ThrowIfNull(page);
        page.SetCurrentValue(ScrollViewer.CanContentScrollProperty, false);
        presenter?.SetCurrentValue(NavigationViewContentPresenter.IsDynamicScrollViewerEnabledProperty, false);
    }
}
