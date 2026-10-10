using System.Windows;
using System.Windows.Controls;

namespace AegisPC.App.Controls;

/// <summary>Presents actual bound scan data with a decorative route; small viewports stack sections and keep scrolling available.</summary>
public partial class ActiveScanSurface : UserControl
{
    /// <summary>Constructs inert presentation and responsive layout without creating a scan view model or security service.</summary>
    public ActiveScanSurface()
    {
        InitializeComponent(); SizeChanged += (_, _) => ArrangePanels();
    }
    private void ArrangePanels()
    {
        bool compact = ActualWidth < 620;
        VisualColumn.Width = compact ? new GridLength(0) : new GridLength(Math.Min(320, ActualWidth * .34));
        MetricsColumn.Width = compact ? new GridLength(0) : new GridLength(Math.Min(210, ActualWidth * .25));
        foreach (var panel in new FrameworkElement[] { RouteVisual, DetailPanel, MetricsPanel })
        {
            Grid.SetColumn(panel, compact ? 1 : panel == RouteVisual ? 0 : panel == DetailPanel ? 1 : 2);
            Grid.SetRow(panel, compact ? panel == RouteVisual ? 0 : panel == DetailPanel ? 1 : 2 : 0);
            panel.Margin = compact ? new Thickness(0, 0, 0, 18) : panel == RouteVisual || panel == DetailPanel ? new Thickness(0, 0, 18, 0) : new Thickness();
        }
        RouteVisual.MaxWidth = compact ? 260 : double.PositiveInfinity;
    }
}
