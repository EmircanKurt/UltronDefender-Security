using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace AegisPC.App.Helpers
{
    /// <summary>
    /// Routes wheel input only to a scrolling ancestor of the actual input source.
    /// Nested controls keep priority, while exhausted viewers pass to a movable
    /// ancestor. Logical item scrolling remains owned by the native control.
    /// </summary>
    public static class WheelScrollHelper
    {
        /// <summary>Enables direction-aware wheel routing on a page's scrolling surface.</summary>
        public static readonly DependencyProperty EnableRootRedirectProperty =
            DependencyProperty.RegisterAttached(
                "EnableRootRedirect",
                typeof(bool),
                typeof(WheelScrollHelper),
                new PropertyMetadata(false, OnEnableRootRedirectChanged));

        /// <summary>Reads whether the element redirects otherwise trapped wheel input.</summary>
        public static bool GetEnableRootRedirect(DependencyObject obj) => (bool)obj.GetValue(EnableRootRedirectProperty);
        /// <summary>Enables or removes the element's local preview-wheel subscription.</summary>
        public static void SetEnableRootRedirect(DependencyObject obj, bool value) => obj.SetValue(EnableRootRedirectProperty, value);

        private static void OnEnableRootRedirectChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            if (d is UIElement element)
            {
                element.PreviewMouseWheel -= Element_PreviewMouseWheel;
                if ((bool)e.NewValue)
                {
                    element.PreviewMouseWheel += Element_PreviewMouseWheel;
                }
            }
        }

        internal static Action<ScrollViewer, double>? OnScrolledForTesting { get; set; }
        internal static Func<ScrollViewer, double>? ScrollableHeightProviderForTesting { get; set; }
        internal static Func<ScrollViewer, double>? VerticalOffsetProviderForTesting { get; set; }

        private static void Element_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            ProcessMouseWheel(sender, e);
        }

        internal static void ProcessMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (e.Handled || e.Delta == 0) return;
            if (sender is not DependencyObject boundary) return;
            DependencyObject? source = (e.OriginalSource as DependencyObject) ?? (e.Source as DependencyObject);
            if (source == null || !IsWithinBoundary(source, boundary)) return;

            for (DependencyObject? current = source; current != null; current = GetParent(current))
            {
                ScrollViewer? viewer = current as ScrollViewer;
                if (viewer == null && current is DataGrid or ListBox or TextBoxBase)
                    viewer = FindFirstVisualChild<ScrollViewer>(current);
                if (viewer == null || !CanMove(viewer, e.Delta, out double offset, out double extent)) continue;

                // VirtualizingStackPanel offsets are item units, not DIP. Let the
                // item's native wheel handler retain virtualization and line policy.
                if (viewer.CanContentScroll) return;
                double scale = ReferenceEquals(viewer, boundary) ? 0.75 : 0.5;
                double target = Math.Clamp(offset - (e.Delta * scale), 0, extent);
                if (Math.Abs(target - offset) < 0.001) continue;
                viewer.ScrollToVerticalOffset(target);
                OnScrolledForTesting?.Invoke(viewer, target);
                e.Handled = true;
                return;
            }
        }

        private static bool CanMove(ScrollViewer viewer, int delta, out double offset, out double extent)
        {
            offset = VerticalOffsetProviderForTesting?.Invoke(viewer) ?? viewer.VerticalOffset;
            extent = ScrollableHeightProviderForTesting?.Invoke(viewer) ?? viewer.ScrollableHeight;
            return viewer.VerticalScrollBarVisibility != ScrollBarVisibility.Disabled
                && double.IsFinite(offset) && double.IsFinite(extent) && extent > 0
                && (delta < 0 ? offset < extent - 0.001 : offset > 0.001);
        }

        private static bool IsWithinBoundary(DependencyObject source, DependencyObject boundary)
        {
            for (DependencyObject? current = source; current != null; current = GetParent(current))
                if (ReferenceEquals(current, boundary)) return true;
            return false;
        }

        internal static DependencyObject? GetParent(DependencyObject element)
        {
            if (element is ContentElement content)
                return ContentOperations.GetParent(content) ?? (content as FrameworkContentElement)?.Parent;
            DependencyObject? visualParent = element is Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(element) : null;
            return visualParent ?? LogicalTreeHelper.GetParent(element);
        }

        /// <summary>
        /// Finds a descendant viewer or control for template inspection. Input routing
        /// still validates the source's ancestor chain before modifying any offsets.
        /// </summary>
        public static T? FindFirstVisualChild<T>(DependencyObject? parent) where T : DependencyObject
        {
            if (parent == null) return null;

            if (parent is not Visual && parent is not System.Windows.Media.Media3D.Visual3D)
            {
                foreach (var logicalChild in LogicalTreeHelper.GetChildren(parent))
                {
                    if (logicalChild is T typed) return typed;
                    if (logicalChild is DependencyObject dep)
                    {
                        var found = FindFirstVisualChild<T>(dep);
                        if (found != null) return found;
                    }
                }
                return null;
            }

            int count = VisualTreeHelper.GetChildrenCount(parent);
            for (int i = 0; i < count; i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is T typedChild) return typedChild;
                var descendant = FindFirstVisualChild<T>(child);
                if (descendant != null) return descendant;
            }
            return null;
        }
    }
}
