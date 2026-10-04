using System;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using AegisPC.App.Helpers;
using Xunit;

namespace AegisPC.Tests;

/// <summary>
/// Measures generated report-table cells with the application's resource dictionaries
/// on isolated STA threads. No application, native window, persisted theme preference,
/// protection service or global mouse input is created by these infrastructure tests.
/// </summary>
public sealed class ReportsTableThemeRegressionTests
{
    /// <summary>Checks the rendered text brush of normal and selected report rows against the current table surface.</summary>
    [Theory]
    [InlineData("Dark")]
    [InlineData("Light")]
    public void ReportRows_NormalAndSelectedTextUsesReadableThemeBrush(string theme) => RunSta(() =>
    {
        var (host, table) = CreateTable(theme);
        var primary = Assert.IsType<SolidColorBrush>(host.FindResource("BrushTextPrimary")).Color;
        var surface = Assert.IsType<SolidColorBrush>(host.FindResource("BrushCardBg")).Color;
        var selection = Assert.IsType<SolidColorBrush>(host.FindResource("BrushCardBorderHover")).Color;
        var normalRow = GetRow(table, 1);
        var normalText = Assert.IsType<TextBlock>(table.Columns[0].GetCellContent(normalRow));
        Assert.False(normalRow.IsSelected);
        Assert.Equal(primary, Assert.IsType<SolidColorBrush>(normalRow.Foreground).Color);
        Assert.Equal(primary, Assert.IsType<SolidColorBrush>(normalText.Foreground).Color);
        Assert.True(ContrastRatio(primary, surface) >= 4.5);

        table.SelectedIndex = 0;
        Layout(host);
        var selectedRow = GetRow(table, 0);
        var selectedText = Assert.IsType<TextBlock>(table.Columns[0].GetCellContent(selectedRow));
        var selectedCell = FindCell(selectedText);
        Assert.True(selectedRow.IsSelected);
        Assert.True(selectedCell.IsSelected);
        Assert.Equal(primary, Assert.IsType<SolidColorBrush>(selectedCell.Foreground).Color);
        Assert.Equal(primary, Assert.IsType<SolidColorBrush>(selectedText.Foreground).Color);
        Assert.Equal(selection, Assert.IsType<SolidColorBrush>(selectedCell.Background).Color);
        Assert.True(ContrastRatio(primary, selection) >= 4.5);
    });

    /// <summary>Checks theme changes update existing normal and selected cells instead of requiring a new table.</summary>
    [Fact]
    public void ReportRows_ExistingCellsFollowThemeDictionaryReplacement() => RunSta(() =>
    {
        var (host, table) = CreateTable("Dark");
        table.SelectedIndex = 0;
        Layout(host);
        host.Resources.MergedDictionaries[2] = LoadResource("Colors.Light.xaml");
        Layout(host);
        // WPF may regenerate column content when the theme styles are invalidated.
        // Inspect the current visual cells, not detached pre-switch TextBlocks.
        var selected = Assert.IsType<TextBlock>(table.Columns[0].GetCellContent(GetRow(table, 0)));
        var normal = Assert.IsType<TextBlock>(table.Columns[0].GetCellContent(GetRow(table, 1)));
        Assert.True(host.IsAncestorOf(selected));
        Assert.True(host.IsAncestorOf(normal));
        var lightText = Assert.IsType<SolidColorBrush>(host.FindResource("BrushTextPrimary")).Color;
        Assert.Equal(lightText, Assert.IsType<SolidColorBrush>(selected.Foreground).Color);
        Assert.Equal(lightText, Assert.IsType<SolidColorBrush>(normal.Foreground).Color);
    });

    /// <summary>Checks the native logical wheel handler moves an overflowing report table with the shared production styles.</summary>
    [Fact]
    public void ReportTable_NativeWheelMovesRowsAndKeepsVirtualization() => RunSta(() =>
    {
        var (host, table) = CreateTable("Dark", 200);
        var viewer = WheelScrollHelper.FindFirstVisualChild<ScrollViewer>(table);
        Assert.NotNull(viewer);
        Assert.True(viewer.CanContentScroll);
        Assert.True(viewer.ScrollableHeight > 0);
        Assert.True(VirtualizingPanel.GetIsVirtualizing(table));
        var input = new System.Windows.Input.MouseWheelEventArgs(
            System.Windows.Input.InputManager.Current.PrimaryMouseDevice, 0, -120)
        {
            RoutedEvent = UIElement.MouseWheelEvent,
            Source = table.Columns[0].GetCellContent(GetRow(table, 0))
        };
        Assert.IsAssignableFrom<UIElement>(input.Source).RaiseEvent(input);
        Layout(host);
        Assert.True(input.Handled);
        Assert.True(viewer.VerticalOffset > 0);
        Assert.InRange(viewer.VerticalOffset, 0, viewer.ScrollableHeight);
        Assert.True(VirtualizingPanel.GetIsVirtualizing(table));
    });

    private static (Grid Host, DataGrid Table) CreateTable(string theme, int count = 4)
    {
        var host = new Grid();
        host.Resources.MergedDictionaries.Add(new Wpf.Ui.Markup.ThemesDictionary());
        host.Resources.MergedDictionaries.Add(new Wpf.Ui.Markup.ControlsDictionary());
        host.Resources.MergedDictionaries.Add(LoadResource($"Colors.{theme}.xaml"));
        host.Resources.MergedDictionaries.Add(LoadResource("Typography.xaml"));
        host.Resources.MergedDictionaries.Add(LoadResource("Components.xaml"));
        host.Resources.MergedDictionaries.Add(LoadResource("SharedStyles.xaml"));
        host.SetResourceReference(Panel.BackgroundProperty, "BrushCardBg");
        var table = new DataGrid
        {
            ItemsSource = Enumerable.Range(0, count).Select(index => $"Report {index}: completed, 0 findings").ToArray(),
            IsReadOnly = true,
            SelectionMode = DataGridSelectionMode.Single,
            AutoGenerateColumns = false,
            CanUserAddRows = false
        };
        table.Columns.Add(new DataGridTextColumn { Header = "Report", Binding = new Binding("."), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        host.Children.Add(table);
        Layout(host);
        return (host, table);
    }

    private static ResourceDictionary LoadResource(string file) => new()
    {
        Source = new Uri($"pack://application:,,,/UltronDefender;component/Resources/Themes/{file}", UriKind.Absolute)
    };

    private static DataGridRow GetRow(DataGrid table, int index) =>
        Assert.IsType<DataGridRow>(table.ItemContainerGenerator.ContainerFromIndex(index));

    private static DataGridCell FindCell(DependencyObject child)
    {
        DependencyObject? current = child;
        while (current != null && current is not DataGridCell)
            current = VisualTreeHelper.GetParent(current);
        return Assert.IsType<DataGridCell>(current);
    }

    private static double ContrastRatio(Color first, Color second)
    {
        static double Channel(byte value)
        {
            double channel = value / 255d;
            return channel <= 0.04045 ? channel / 12.92 : Math.Pow((channel + 0.055) / 1.055, 2.4);
        }
        static double Luminance(Color color) => 0.2126 * Channel(color.R) + 0.7152 * Channel(color.G) + 0.0722 * Channel(color.B);
        double a = Luminance(first), b = Luminance(second);
        return (Math.Max(a, b) + 0.05) / (Math.Min(a, b) + 0.05);
    }

    private static void Layout(FrameworkElement element)
    {
        element.Measure(new Size(600, 200));
        element.Arrange(new Rect(0, 0, 600, 200));
        element.UpdateLayout();
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
        element.UpdateLayout();
    }

    private static void RunSta(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception exception) { failure = exception; }
            finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); }
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "The isolated offscreen report-table check exceeded its budget.");
        if (failure != null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
