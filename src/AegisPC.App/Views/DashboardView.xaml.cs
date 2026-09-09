using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class DashboardView : Page
    {
        public DashboardViewModel ViewModel { get; }

        public DashboardView() : this(new DashboardViewModel())
        {
        }

        public DashboardView(DashboardViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }

        private void OnPagePreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (RootScrollViewer == null || e.Delta == 0) return;

            DependencyObject? cur = e.OriginalSource as DependencyObject;
            ScrollViewer? childScroll = null;
            while (cur != null && cur != RootScrollViewer)
            {
                if (cur is DataGrid dg)
                {
                    childScroll = FindVisualChild<ScrollViewer>(dg);
                    break;
                }
                cur = cur is Visual || cur is System.Windows.Media.Media3D.Visual3D
                    ? VisualTreeHelper.GetParent(cur)
                    : System.Windows.LogicalTreeHelper.GetParent(cur);
            }

            if (childScroll != null && childScroll.ScrollableHeight > 0)
            {
                bool canScrollDown = e.Delta < 0 && childScroll.VerticalOffset < childScroll.ScrollableHeight;
                bool canScrollUp = e.Delta > 0 && childScroll.VerticalOffset > 0;

                if (canScrollDown || canScrollUp)
                {
                    // Let child DataGrid handle or scroll it directly
                    childScroll.ScrollToVerticalOffset(childScroll.VerticalOffset - (e.Delta * 0.5));
                    e.Handled = true;
                    return;
                }
            }

            RootScrollViewer.ScrollToVerticalOffset(RootScrollViewer.VerticalOffset - (e.Delta * 0.75));
            e.Handled = true;
        }

        private void OnDataGridPreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (e.Delta == 0) return;

            if (sender is DependencyObject dep)
            {
                var sv = FindVisualChild<ScrollViewer>(dep);
                if (sv != null && sv.ScrollableHeight > 0)
                {
                    if (e.Delta < 0 && sv.VerticalOffset < sv.ScrollableHeight)
                    {
                        sv.ScrollToVerticalOffset(Math.Min(sv.ScrollableHeight, sv.VerticalOffset + 38));
                        e.Handled = true;
                        return;
                    }
                    if (e.Delta > 0 && sv.VerticalOffset > 0)
                    {
                        sv.ScrollToVerticalOffset(Math.Max(0, sv.VerticalOffset - 38));
                        e.Handled = true;
                        return;
                    }
                }
            }

            if (RootScrollViewer != null)
            {
                RootScrollViewer.ScrollToVerticalOffset(RootScrollViewer.VerticalOffset - (e.Delta * 0.75));
                e.Handled = true;
            }
        }

        private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
        {
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                DependencyObject child = VisualTreeHelper.GetChild(parent, i);
                if (child is T typedChild) return typedChild;
                var found = FindVisualChild<T>(child);
                if (found != null) return found;
            }
            return null;
        }
    }
}
