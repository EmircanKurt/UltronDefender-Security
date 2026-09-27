using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace AegisPC.App.Helpers
{
    /// <summary>
    /// Sayfa ve kontroller genelinde fare tekerleği (MouseWheel) kaydırmasını
    /// tek merkezden yöneten yardımcı sınıf.
    /// İç içe geçmiş kaydırıcılarda (DataGrid, ListBox, ListView, iç ScrollViewer)
    /// iç kontrol önceliğini korur; iç kontrol sonuna geldiğinde veya iç kontrol
    /// olmadığında kök ScrollViewer'ı kesintisiz kaydırır.
    /// </summary>
    public static class WheelScrollHelper
    {
        public static readonly DependencyProperty EnableRootRedirectProperty =
            DependencyProperty.RegisterAttached(
                "EnableRootRedirect",
                typeof(bool),
                typeof(WheelScrollHelper),
                new PropertyMetadata(false, OnEnableRootRedirectChanged));

        public static bool GetEnableRootRedirect(DependencyObject obj) => (bool)obj.GetValue(EnableRootRedirectProperty);
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
            if (sender is not DependencyObject d) return;

            // 1. Kök ScrollViewer'ı otomatik bul (ağaçta ilk ScrollViewer veya kendisi)
            ScrollViewer? rootScrollViewer = d as ScrollViewer ?? FindFirstVisualChild<ScrollViewer>(d);
            if (rootScrollViewer == null) return;

            // 2. Tekerlek kaynağının üzerinde iç kaydırıcı (DataGrid, ListBox, ListView veya iç ScrollViewer) var mı?
            DependencyObject? cur = (e.OriginalSource as DependencyObject) ?? (e.Source as DependencyObject);
            ScrollViewer? childScroll = null;

            while (cur != null && cur != rootScrollViewer)
            {
                if (cur is ScrollViewer sv && sv != rootScrollViewer)
                {
                    childScroll = sv;
                    break;
                }

                if (cur is DataGrid dg)
                {
                    childScroll = FindFirstVisualChild<ScrollViewer>(dg);
                    if (childScroll != null && childScroll != rootScrollViewer)
                        break;
                }
                else if (cur is ListBox or ListView)
                {
                    childScroll = FindFirstVisualChild<ScrollViewer>(cur);
                    if (childScroll != null && childScroll != rootScrollViewer)
                        break;
                }

                DependencyObject? parent = (cur is Visual || cur is System.Windows.Media.Media3D.Visual3D)
                    ? VisualTreeHelper.GetParent(cur)
                    : null;
                cur = parent ?? LogicalTreeHelper.GetParent(cur);
            }

            // 3. İç içe kaydırıcı kuralı:
            // İç ScrollViewer kaydırılabilir içerikten fazlaysa iç kaydırır, sonuna gelince kök devam etsin
            double childScrollableHeight = childScroll != null
                ? (ScrollableHeightProviderForTesting?.Invoke(childScroll) ?? childScroll.ScrollableHeight)
                : 0;
            double childVerticalOffset = childScroll != null
                ? (VerticalOffsetProviderForTesting?.Invoke(childScroll) ?? childScroll.VerticalOffset)
                : 0;

            if (childScroll != null && childScrollableHeight > 0)
            {
                bool canScrollDown = e.Delta < 0 && childVerticalOffset < childScrollableHeight;
                bool canScrollUp = e.Delta > 0 && childVerticalOffset > 0;

                if (canScrollDown || canScrollUp)
                {
                    // İç ScrollViewer önceliği: iç kaydırılır
                    double childOffset = childVerticalOffset - (e.Delta * 0.5);
                    double targetChildOffset = Math.Clamp(childOffset, 0, childScrollableHeight);
                    childScroll.ScrollToVerticalOffset(targetChildOffset);
                    OnScrolledForTesting?.Invoke(childScroll, targetChildOffset);
                    e.Handled = true;
                    return;
                }
                // İç kaydırıcı sonuna gelmişse kök ScrollViewer'ın devam etmesine izin ver
            }

            // 4. Kök ScrollViewer'ı kaydır
            double rootScrollableHeight = ScrollableHeightProviderForTesting?.Invoke(rootScrollViewer) ?? rootScrollViewer.ScrollableHeight;
            double rootVerticalOffset = VerticalOffsetProviderForTesting?.Invoke(rootScrollViewer) ?? rootScrollViewer.VerticalOffset;

            double newOffset = rootVerticalOffset - (e.Delta * 0.75);
            double max = rootScrollableHeight > 0 ? rootScrollableHeight : double.MaxValue;
            double targetRootOffset = Math.Clamp(newOffset, 0, max);
            rootScrollViewer.ScrollToVerticalOffset(targetRootOffset);
            OnScrolledForTesting?.Invoke(rootScrollViewer, targetRootOffset);
            e.Handled = true;
        }

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
