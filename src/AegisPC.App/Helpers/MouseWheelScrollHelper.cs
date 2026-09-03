using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace AegisPC.App.Helpers
{
    /// <summary>
    /// İç içe geçmiş kontrollerde (özellikle salt-okunur TextBox'lar ve paneller)
    /// fare tekerleği olayının yutulmasını engelleyip ebeveyn ScrollViewer'a ileten yardımcı sınıf.
    /// </summary>
    public static class MouseWheelScrollHelper
    {
        public static readonly DependencyProperty BubbleScrollProperty =
            DependencyProperty.RegisterAttached(
                "BubbleScroll",
                typeof(bool),
                typeof(MouseWheelScrollHelper),
                new PropertyMetadata(false, OnBubbleScrollChanged));

        public static bool GetBubbleScroll(DependencyObject obj) => (bool)obj.GetValue(BubbleScrollProperty);
        public static void SetBubbleScroll(DependencyObject obj, bool value) => obj.SetValue(BubbleScrollProperty, value);

        private static void OnBubbleScrollChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            if (d is UIElement element)
            {
                if ((bool)e.NewValue)
                {
                    element.PreviewMouseWheel += Element_PreviewMouseWheel;
                }
                else
                {
                    element.PreviewMouseWheel -= Element_PreviewMouseWheel;
                }
            }
        }

        private static void Element_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (sender is DependencyObject d && e.Delta != 0)
            {
                var scrollViewer = FindParentScrollViewer(d);
                if (scrollViewer != null)
                {
                    double offset = scrollViewer.VerticalOffset - (e.Delta * 0.75);
                    scrollViewer.ScrollToVerticalOffset(offset);
                    e.Handled = true;
                }
            }
        }

        public static ScrollViewer? FindParentScrollViewer(DependencyObject? child)
        {
            if (child == null) return null;
            DependencyObject? parent = VisualTreeHelper.GetParent(child);
            while (parent != null)
            {
                if (parent is ScrollViewer sv) return sv;
                parent = VisualTreeHelper.GetParent(parent);
            }
            return null;
        }
    }
}
