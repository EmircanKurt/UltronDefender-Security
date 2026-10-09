using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Threading;
using System.Xml.Linq;
using AegisPC.App.Services;
using Wpf.Ui.Controls;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Offscreen production palette/native collection tests; never starts App/MainWindow or persists a theme.</summary>
public sealed class NativeSidebarStateReviewTests
{
    /// <summary>Native menu and footer states retain readable text/icons after theme and pane transitions.</summary>
    [Fact]
    public void ActualNativeCollectionsRetainContrastAndRefreshAllBrushes()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { Verify(); } catch (Exception ex) { failure = ex; }
            finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); }
        });
        thread.SetApartmentState(ApartmentState.STA); thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(20)), "Native fixture timed out.");
        if (failure != null) ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private static void Verify()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root != null && !File.Exists(Path.Combine(root.FullName, "AegisPC.sln"))) root = root.Parent;
        var doc = XDocument.Load(Path.Combine(root!.FullName, "src/AegisPC.App/MainWindow.xaml"));
        XNamespace w = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace x = "http://schemas.microsoft.com/winfx/2006/xaml";
        var element = new XElement(doc.Descendants(w + "Style").Single(e => (string?)e.Attribute(x + "Key") == "UltronSidebarItemStyle"));
        element.SetAttributeValue(XNamespace.Xmlns + "ui", "http://schemas.lepo.co/wpfui/2022/xaml");
        element.SetAttributeValue(XNamespace.Xmlns + "x", x.NamespaceName);
        var style = (Style)XamlReader.Parse(element.ToString().Replace("{StaticResource FontSans}", "Segoe UI"));
        var nav = new NavigationView { OpenPaneLength = 240, IsPaneOpen = true, IsPaneToggleVisible = false, PaneDisplayMode = NavigationViewPaneDisplayMode.Left };
        var host = new Border { Child = nav };
        host.Resources.MergedDictionaries.Add((ResourceDictionary)XamlReader.Parse("<ResourceDictionary xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' xmlns:ui='http://schemas.lepo.co/wpfui/2022/xaml'><ResourceDictionary.MergedDictionaries><ui:ThemesDictionary Theme='Light'/><ui:ControlsDictionary/></ResourceDictionary.MergedDictionaries></ResourceDictionary>"));
        var menu = Make(style, "Tarayıcı"); var footer = Make(style, "Ayarlar");
        nav.MenuItems.Add(menu); nav.FooterMenuItems.Add(footer);
        foreach (bool dark in new[] { false, true, false })
        {
            ThemePalette.Apply(host.Resources, dark);
            foreach (var mode in new[] { NavigationViewPaneDisplayMode.Left, NavigationViewPaneDisplayMode.LeftMinimal, NavigationViewPaneDisplayMode.Left })
            {
                nav.PaneDisplayMode = mode; nav.IsPaneOpen = true;
                foreach (var item in new[] { menu, footer })
                foreach (bool active in new[] { false, true })
                foreach (bool hover in new[] { false, true })
                foreach (bool focused in new[] { false, true })
                {
                    item.IsActive = active; item.ForceMouseOver(hover); item.ForceKeyboardFocus(focused); Layout(host);
                    Assert.NotNull(item.Template.FindName("MainBorder", item));
                    var border = (Border)item.Template.FindName("MainBorder", item);
                    var background = border.Background as SolidColorBrush;
                    var actualBg = background?.Color.A > 0 ? background.Color : ((SolidColorBrush)host.FindResource("BrushSidebarBg")).Color;
                    Assert.True(Contrast(((SolidColorBrush)item.Foreground).Color, actualBg) >= 4.5, $"{dark}/{mode}/{item.Content}/{active}/{hover}");
                    Assert.True(Contrast(((SolidColorBrush)item.Icon!.Foreground).Color, actualBg) >= 4.5);
                    Assert.True(item.Focusable && item.IsTabStop);
                }
            }
        }
    }

    private static Probe Make(Style style, string label)
    {
        var icon = new SymbolIcon(SymbolRegular.Search24);
        icon.SetResourceReference(Control.ForegroundProperty, "BrushSidebarTextSecondary");
        return new Probe { Content = label, Style = style, Icon = icon };
    }
    private static void Layout(FrameworkElement host)
    {
        for (int i = 0; i < 3; i++)
        {
            host.Measure(new Size(400, 760)); host.Arrange(new Rect(0, 0, 400, 760)); host.UpdateLayout();
            var frame = new DispatcherFrame(); Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false)); Dispatcher.PushFrame(frame);
        }
    }
    private static double Contrast(Color a, Color b)
    {
        static double L(Color c) { static double S(byte v) { double x = v / 255d; return x <= .04045 ? x / 12.92 : Math.Pow((x + .055) / 1.055, 2.4); } return .2126 * S(c.R) + .7152 * S(c.G) + .0722 * S(c.B); }
        return (Math.Max(L(a), L(b)) + .05) / (Math.Min(L(a), L(b)) + .05);
    }
    private sealed class Probe : NavigationViewItem
    {
        // Inert trigger probe, not OS input; actual live DPI/input remains a separate acceptance gate.
        internal void ForceMouseOver(bool value) => SetValue((DependencyPropertyKey)typeof(UIElement)
            .GetField("IsMouseOverPropertyKey", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!, value);
        internal void ForceKeyboardFocus(bool value) => SetValue((DependencyPropertyKey)typeof(UIElement)
            .GetField("IsKeyboardFocusedPropertyKey", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!, value);
    }
}
