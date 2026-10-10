using System.Windows;
using System.Windows.Controls;

namespace AegisPC.App.Controls;

/// <summary>Inert, responsive dashboard presentation; it does not create services or start scans.</summary>
public partial class PlainDashboardSurface : UserControl
{
    /// <summary>Initializes native controls and responsive layout only.</summary>
    public PlainDashboardSurface()
    {
        InitializeComponent();
        SizeChanged += OnSurfaceSizeChanged;
    }

    private void OnSurfaceSizeChanged(object sender, SizeChangedEventArgs args)
    {
        bool stacked = args.NewSize.Width < 680;
        Grid.SetColumn(RefreshButton, stacked ? 0 : 1);
        Grid.SetRow(RefreshButton, stacked ? 1 : 0);
        RefreshButton.Margin = new Thickness(stacked ? 0 : 18, stacked ? 14 : 0, 0, 0);
        DetailGrid.ColumnDefinitions[1].Width = new GridLength(stacked ? 0 : 18);
        DetailGrid.ColumnDefinitions[2].Width = stacked ? new GridLength(0) : new GridLength(1, GridUnitType.Star);
        Grid.SetColumn(EventsPanel, stacked ? 0 : 2);
        Grid.SetRow(EventsPanel, stacked ? 1 : 0);
        EventsPanel.Margin = new Thickness(0, stacked ? 18 : 0, 0, 0);
    }
}
