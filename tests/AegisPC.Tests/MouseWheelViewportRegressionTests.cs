using System;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Threading;
using AegisPC.App.Helpers;
using Wpf.Ui.Controls;
using TextBlock = System.Windows.Controls.TextBlock;
using TextBox = System.Windows.Controls.TextBox;
using ListBox = System.Windows.Controls.ListBox;
using Size = System.Windows.Size;
using Xunit;

namespace AegisPC.Tests;

/// <summary>
/// Exercises actual offscreen WPF layout and local routed wheel events on isolated
/// STA threads. No application, native window, protection service or global input
/// hook is started; these cases measure UI infrastructure, not malware detection.
/// </summary>
public sealed class MouseWheelViewportRegressionTests
{
    /// <summary>Reproduces the library's unbounded outer viewport and verifies the page-owned policy restores a real inner range.</summary>
    [Fact]
    public void NavigationLibraryViewport_PageOwnedPolicyRestoresInnerScrollableRange() => RunSta(() =>
    {
        var content = new Border { Height = 800 };
        var viewer = CreateViewer(content);
        var page = new Page { Content = viewer };
        var presenter = new NavigationViewContentPresenter();
        presenter.Resources.MergedDictionaries.Add(new Wpf.Ui.Markup.ThemesDictionary());
        presenter.Resources.MergedDictionaries.Add(new Wpf.Ui.Markup.ControlsDictionary());
        presenter.Style = Assert.IsType<Style>(presenter.FindResource(typeof(NavigationViewContentPresenter)));
        Assert.True(presenter.Navigate(page));
        Pump();
        Layout(presenter);
        Assert.Same(page, presenter.Content);
        Assert.True(presenter.IsDynamicScrollViewerEnabled);
        Assert.Equal(0, viewer.ScrollableHeight);

        NavigationScrollPolicy.ConfigurePageOwnedScrolling(page, presenter);
        presenter.ApplyTemplate();
        Layout(presenter);

        Assert.False(presenter.IsDynamicScrollViewerEnabled);
        Assert.True(viewer.ScrollableHeight > 0);
        Assert.True(RaiseWheel(content, -120).Handled);
        Pump();
        presenter.UpdateLayout();
        Assert.True(viewer.VerticalOffset > 0);
    });

    /// <summary>Checks that page-owned scrolling explicitly disables the library's extra viewport.</summary>
    [Fact]
    public void PageOwnedScrolling_DisablesNavigationWrapperWithoutChangingItemVirtualization() => RunSta(() =>
    {
        var presenter = new NavigationViewContentPresenter();
        var page = new Page();
        var list = new ListBox();
        ScrollViewer.SetCanContentScroll(list, true);
        VirtualizingPanel.SetIsVirtualizing(list, true);
        page.Content = list;
        Assert.True(presenter.IsDynamicScrollViewerEnabled);

        NavigationScrollPolicy.ConfigurePageOwnedScrolling(page, presenter);

        Assert.False(presenter.IsDynamicScrollViewerEnabled);
        Assert.False(ScrollViewer.GetCanContentScroll(page));
        Assert.True(ScrollViewer.GetCanContentScroll(list));
        Assert.True(VirtualizingPanel.GetIsVirtualizing(list));
    });

    /// <summary>Checks finite layout and actual offset movement for a page's own content viewer.</summary>
    [Fact]
    public void PageViewport_ActualWheelMovesScrollableContent() => RunSta(() =>
    {
        var content = new Border { Height = 800 };
        var viewer = CreateViewer(content);
        var page = new Page { Content = viewer };
        NavigationScrollPolicy.ConfigurePageOwnedScrolling(page, null);
        Layout(page);
        Assert.True(viewer.ScrollableHeight > 0);

        var input = RaiseWheel(content, -120);
        Pump();
        viewer.UpdateLayout();

        Assert.True(input.Handled);
        Assert.True(viewer.VerticalOffset > 0);
        Assert.InRange(viewer.VerticalOffset, 0, viewer.ScrollableHeight);
    });

    /// <summary>Checks that a viewer with no overflow does not claim to consume a scrolling action.</summary>
    [Fact]
    public void ZeroScrollableExtent_DoesNotSwallowWheel() => RunSta(() =>
    {
        var content = new Border { Height = 20 };
        var viewer = CreateViewer(content);
        Layout(viewer);
        Assert.Equal(0, viewer.ScrollableHeight);

        var input = RaiseWheel(content, -120);

        Assert.False(input.Handled);
        Assert.Equal(0, viewer.VerticalOffset);
    });

    /// <summary>Checks that an inner content viewer takes priority while it can move in the requested direction.</summary>
    [Fact]
    public void NestedContent_InnerViewerMovesBeforeOuterViewer() => RunSta(() =>
    {
        var content = new Border { Height = 600 };
        var inner = CreateViewer(content);
        inner.Height = 100;
        var panel = new StackPanel();
        panel.Children.Add(inner);
        panel.Children.Add(new Border { Height = 800 });
        var outer = CreateViewer(panel);
        Layout(outer);

        var input = RaiseWheel(content, -120);
        Pump();
        outer.UpdateLayout();

        Assert.True(input.Handled);
        Assert.True(inner.VerticalOffset > 0);
        Assert.Equal(0, outer.VerticalOffset);
    });

    /// <summary>Checks bottom-boundary propagation to a movable ancestor using measured WPF offsets.</summary>
    [Fact]
    public void NestedBottomBoundary_OuterViewerContinuesScrolling() => RunSta(() =>
    {
        var content = new Border { Height = 600 };
        var inner = CreateViewer(content);
        inner.Height = 100;
        var panel = new StackPanel();
        panel.Children.Add(inner);
        panel.Children.Add(new Border { Height = 800 });
        var outer = CreateViewer(panel);
        Layout(outer);
        inner.ScrollToBottom();
        Pump();
        outer.UpdateLayout();
        Assert.Equal(inner.ScrollableHeight, inner.VerticalOffset);

        var input = RaiseWheel(content, -120);
        Pump();
        outer.UpdateLayout();

        Assert.True(input.Handled);
        Assert.Equal(inner.ScrollableHeight, inner.VerticalOffset);
        Assert.True(outer.VerticalOffset > 0);
    });

    /// <summary>Checks that moving an outer viewport remains possible even when the attached inner viewport has no overflow.</summary>
    [Fact]
    public void EmptyInnerViewport_PropagatesToOuterScrollingAncestor() => RunSta(() =>
    {
        var content = new Border { Height = 20 };
        var inner = CreateViewer(content);
        inner.Height = 100;
        var panel = new StackPanel();
        panel.Children.Add(inner);
        panel.Children.Add(new Border { Height = 800 });
        var outer = CreateViewer(panel);
        WheelScrollHelper.SetEnableRootRedirect(outer, false);
        Layout(outer);
        Assert.Equal(0, inner.ScrollableHeight);

        var input = RaiseWheel(content, -120);
        Pump();
        outer.UpdateLayout();

        Assert.True(input.Handled);
        Assert.Equal(0, inner.VerticalOffset);
        Assert.True(outer.VerticalOffset > 0);
    });

    /// <summary>Checks that logical item offsets are not advanced as though they were pixel offsets.</summary>
    [Fact]
    public void VirtualizedList_WheelIsLeftToNativeLogicalScrolling() => RunSta(() =>
    {
        var list = new ListBox { Height = 100, ItemsSource = Enumerable.Range(0, 200).ToArray() };
        ScrollViewer.SetCanContentScroll(list, true);
        VirtualizingPanel.SetIsVirtualizing(list, true);
        var panel = new StackPanel();
        panel.Children.Add(list);
        panel.Children.Add(new Border { Height = 800 });
        var outer = CreateViewer(panel);
        Layout(outer);
        list.ApplyTemplate();
        outer.UpdateLayout();
        var inner = WheelScrollHelper.FindFirstVisualChild<ScrollViewer>(list);
        Assert.NotNull(inner);
        Assert.True(inner.CanContentScroll);
        Assert.True(inner.ScrollableHeight > 0);

        var input = RaiseWheel(list, -120);

        Assert.False(input.Handled);
        Assert.Equal(0, outer.VerticalOffset);
        Assert.True(VirtualizingPanel.GetIsVirtualizing(list));
    });

    /// <summary>Checks text-content parent traversal instead of assuming every event source is a visual.</summary>
    [Fact]
    public void TextRunSource_UsesItsActualScrollingAncestor() => RunSta(() =>
    {
        var run = new Run("Details");
        var text = new TextBlock(run);
        var panel = new StackPanel();
        panel.Children.Add(text);
        panel.Children.Add(new Border { Height = 800 });
        var viewer = CreateViewer(panel);
        Layout(viewer);
        Assert.Same(viewer, MouseWheelScrollHelper.FindParentScrollViewer(run));

        var input = new MouseWheelEventArgs(InputManager.Current.PrimaryMouseDevice, 0, -120)
        {
            RoutedEvent = UIElement.PreviewMouseWheelEvent,
            Source = run
        };
        text.RaiseEvent(input);
        Pump();
        viewer.UpdateLayout();

        Assert.True(input.Handled);
        Assert.True(viewer.VerticalOffset > 0);
    });

    /// <summary>Checks that an already consumed event does not trigger a second read-only text redirection.</summary>
    [Fact]
    public void TextBubble_AlreadyHandledWheelDoesNotScrollAgain() => RunSta(() =>
    {
        var text = new TextBox { Text = "Details", IsReadOnly = true, Height = 24 };
        MouseWheelScrollHelper.SetBubbleScroll(text, true);
        var panel = new StackPanel();
        panel.Children.Add(text);
        panel.Children.Add(new Border { Height = 800 });
        var viewer = CreateViewer(panel);
        WheelScrollHelper.SetEnableRootRedirect(viewer, false);
        Layout(viewer);

        RaiseWheel(text, -120, handled: true);
        Pump();
        viewer.UpdateLayout();

        Assert.Equal(0, viewer.VerticalOffset);
    });

    private static ScrollViewer CreateViewer(object content)
    {
        var viewer = new ScrollViewer
        {
            Content = content,
            CanContentScroll = false,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
        };
        WheelScrollHelper.SetEnableRootRedirect(viewer, true);
        return viewer;
    }

    private static void Layout(FrameworkElement element)
    {
        element.Measure(new Size(350, 160));
        element.Arrange(new Rect(0, 0, 350, 160));
        element.UpdateLayout();
        Pump();
        element.UpdateLayout();
    }

    private static MouseWheelEventArgs RaiseWheel(UIElement source, int delta, bool handled = false)
    {
        var input = new MouseWheelEventArgs(InputManager.Current.PrimaryMouseDevice, 0, delta)
        {
            RoutedEvent = UIElement.PreviewMouseWheelEvent,
            Source = source,
            Handled = handled
        };
        source.RaiseEvent(input);
        return input;
    }

    private static void Pump()
    {
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
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
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "The isolated offscreen scrolling check exceeded its budget.");
        if (failure != null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
