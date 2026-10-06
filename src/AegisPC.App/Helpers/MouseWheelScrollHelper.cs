using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace AegisPC.App.Helpers
{
    /// <summary>
    /// Shares the page's direction-aware wheel policy for nested read-only text
    /// controls without consuming already-handled input or immovable viewers.
    /// </summary>
    public static class MouseWheelScrollHelper
    {
        /// <summary>Enables local wheel propagation from nested text controls.</summary>
        public static readonly DependencyProperty BubbleScrollProperty =
            DependencyProperty.RegisterAttached(
                "BubbleScroll",
                typeof(bool),
                typeof(MouseWheelScrollHelper),
                new PropertyMetadata(false, OnBubbleScrollChanged));

        /// <summary>Reads whether the control uses shared wheel propagation.</summary>
        public static bool GetBubbleScroll(DependencyObject obj) => (bool)obj.GetValue(BubbleScrollProperty);
        /// <summary>Installs or removes the control's local propagation subscription.</summary>
        public static void SetBubbleScroll(DependencyObject obj, bool value) => obj.SetValue(BubbleScrollProperty, value);

        private static void OnBubbleScrollChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
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

        private static void Element_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            WheelScrollHelper.ProcessMouseWheel(sender, e);
        }

        /// <summary>Finds the nearest visual or logical scrolling ancestor, including text content parents.</summary>
        public static ScrollViewer? FindParentScrollViewer(DependencyObject? child)
        {
            if (child == null) return null;
            DependencyObject? parent = WheelScrollHelper.GetParent(child);
            while (parent != null)
            {
                if (parent is ScrollViewer sv) return sv;
                parent = WheelScrollHelper.GetParent(parent);
            }
            return null;
        }
    }
}
