using System;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using AegisPC.App.Helpers;
using Xunit;

namespace AegisPC.Tests
{
    public class WheelScrollHelperTests
    {
        private static void RunInSta(Action action)
        {
            Exception? ex = null;
            var thread = new Thread(() =>
            {
                try
                {
                    if (System.Windows.Application.Current == null)
                    {
                        new System.Windows.Application();
                    }
                    action();
                }
                catch (Exception e)
                {
                    ex = e;
                }
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join();

            if (ex != null)
            {
                throw new AggregateException("STA thread execution failed", ex);
            }
        }

        private static MouseWheelEventArgs CreateWheelArgs(int delta, object? source = null)
        {
            var device = InputManager.Current.PrimaryMouseDevice;
            var args = new MouseWheelEventArgs(device, Environment.TickCount, delta)
            {
                RoutedEvent = UIElement.PreviewMouseWheelEvent
            };
            if (source != null)
            {
                args.Source = source;
            }
            return args;
        }

        [Fact]
        public void EnableRootRedirect_AttachedProperty_CanGetAndSet()
        {
            RunInSta(() =>
            {
                var scrollViewer = new ScrollViewer();
                Assert.False(WheelScrollHelper.GetEnableRootRedirect(scrollViewer));

                WheelScrollHelper.SetEnableRootRedirect(scrollViewer, true);
                Assert.True(WheelScrollHelper.GetEnableRootRedirect(scrollViewer));

                WheelScrollHelper.SetEnableRootRedirect(scrollViewer, false);
                Assert.False(WheelScrollHelper.GetEnableRootRedirect(scrollViewer));
            });
        }

        [Fact]
        public void PropertyFalse_DoesNotInterceptPreviewMouseWheel()
        {
            RunInSta(() =>
            {
                var scrollViewer = new ScrollViewer();
                WheelScrollHelper.SetEnableRootRedirect(scrollViewer, false);

                var args = CreateWheelArgs(-120, scrollViewer);
                scrollViewer.RaiseEvent(args);

                Assert.False(args.Handled, "When EnableRootRedirect is false, the event must not be marked handled.");
            });
        }

        [Fact]
        public void DirectRootScroll_ScrollsRootAndMarksHandled()
        {
            RunInSta(() =>
            {
                var rootScrollViewer = new ScrollViewer();
                ScrollViewer? scrolledTarget = null;
                double scrolledOffset = -1;

                WheelScrollHelper.OnScrolledForTesting = (target, offset) =>
                {
                    scrolledTarget = target;
                    scrolledOffset = offset;
                };

                try
                {
                    var args = CreateWheelArgs(-120, rootScrollViewer);
                    WheelScrollHelper.ProcessMouseWheel(rootScrollViewer, args);

                    Assert.True(args.Handled);
                    Assert.Same(rootScrollViewer, scrolledTarget);
                    // Delta: -120 -> newOffset = 0 - (-120 * 0.75) = 90
                    Assert.Equal(90.0, scrolledOffset);
                }
                finally
                {
                    WheelScrollHelper.OnScrolledForTesting = null;
                }
            });
        }

        [Fact]
        public void InnerControlWithContent_TakesPriorityOverRoot()
        {
            RunInSta(() =>
            {
                var rootScrollViewer = new ScrollViewer();
                var stackPanel = new StackPanel();
                var childScrollViewer = new ScrollViewer();
                var textInsideChild = new TextBlock { Text = "Inner Text" };

                childScrollViewer.Content = textInsideChild;
                stackPanel.Children.Add(childScrollViewer);
                rootScrollViewer.Content = stackPanel;

                ScrollViewer? scrolledTarget = null;
                double scrolledOffset = -1;

                WheelScrollHelper.OnScrolledForTesting = (target, offset) =>
                {
                    scrolledTarget = target;
                    scrolledOffset = offset;
                };
                WheelScrollHelper.ScrollableHeightProviderForTesting = sv => sv == childScrollViewer ? 200 : 500;
                WheelScrollHelper.VerticalOffsetProviderForTesting = sv => sv == childScrollViewer ? 50 : 0;

                try
                {
                    // Scroll down (delta < 0), child is at offset 50 of 200 -> can scroll down
                    var args = CreateWheelArgs(-120, textInsideChild);
                    WheelScrollHelper.ProcessMouseWheel(rootScrollViewer, args);

                    Assert.True(args.Handled);
                    Assert.Same(childScrollViewer, scrolledTarget);
                    // Delta: -120 -> childOffset = 50 - (-120 * 0.5) = 110
                    Assert.Equal(110.0, scrolledOffset);
                }
                finally
                {
                    WheelScrollHelper.OnScrolledForTesting = null;
                    WheelScrollHelper.ScrollableHeightProviderForTesting = null;
                    WheelScrollHelper.VerticalOffsetProviderForTesting = null;
                }
            });
        }

        [Fact]
        public void InnerControlAtBottomBoundary_FallsThroughToRoot()
        {
            RunInSta(() =>
            {
                var rootScrollViewer = new ScrollViewer();
                var stackPanel = new StackPanel();
                var childScrollViewer = new ScrollViewer();
                var textInsideChild = new TextBlock { Text = "Inner Text at bottom" };

                childScrollViewer.Content = textInsideChild;
                stackPanel.Children.Add(childScrollViewer);
                rootScrollViewer.Content = stackPanel;

                ScrollViewer? scrolledTarget = null;
                double scrolledOffset = -1;

                WheelScrollHelper.OnScrolledForTesting = (target, offset) =>
                {
                    scrolledTarget = target;
                    scrolledOffset = offset;
                };
                WheelScrollHelper.ScrollableHeightProviderForTesting = sv => sv == childScrollViewer ? 200 : 500;
                WheelScrollHelper.VerticalOffsetProviderForTesting = sv => sv == childScrollViewer ? 200 : 0; // At bottom boundary

                try
                {
                    // Scroll down (delta < 0), child is already at bottom boundary (200 of 200)
                    var args = CreateWheelArgs(-120, textInsideChild);
                    WheelScrollHelper.ProcessMouseWheel(rootScrollViewer, args);

                    Assert.True(args.Handled);
                    // Must fall through to root!
                    Assert.Same(rootScrollViewer, scrolledTarget);
                    // Delta: -120 -> rootOffset = 0 - (-120 * 0.75) = 90
                    Assert.Equal(90.0, scrolledOffset);
                }
                finally
                {
                    WheelScrollHelper.OnScrolledForTesting = null;
                    WheelScrollHelper.ScrollableHeightProviderForTesting = null;
                    WheelScrollHelper.VerticalOffsetProviderForTesting = null;
                }
            });
        }

        [Fact]
        public void InnerControlAtTopBoundary_FallsThroughToRootWhenScrollingUp()
        {
            RunInSta(() =>
            {
                var rootScrollViewer = new ScrollViewer();
                var stackPanel = new StackPanel();
                var childScrollViewer = new ScrollViewer();
                var textInsideChild = new TextBlock { Text = "Inner Text at top" };

                childScrollViewer.Content = textInsideChild;
                stackPanel.Children.Add(childScrollViewer);
                rootScrollViewer.Content = stackPanel;

                ScrollViewer? scrolledTarget = null;
                double scrolledOffset = -1;

                WheelScrollHelper.OnScrolledForTesting = (target, offset) =>
                {
                    scrolledTarget = target;
                    scrolledOffset = offset;
                };
                WheelScrollHelper.ScrollableHeightProviderForTesting = sv => sv == childScrollViewer ? 200 : 500;
                WheelScrollHelper.VerticalOffsetProviderForTesting = sv => sv == childScrollViewer ? 0 : 100; // child at top boundary, root at 100

                try
                {
                    // Scroll up (delta > 0), child is at 0 -> cannot scroll up
                    var args = CreateWheelArgs(120, textInsideChild);
                    WheelScrollHelper.ProcessMouseWheel(rootScrollViewer, args);

                    Assert.True(args.Handled);
                    // Must fall through to root!
                    Assert.Same(rootScrollViewer, scrolledTarget);
                    // Delta: 120 -> rootOffset = 100 - (120 * 0.75) = 10
                    Assert.Equal(10.0, scrolledOffset);
                }
                finally
                {
                    WheelScrollHelper.OnScrolledForTesting = null;
                    WheelScrollHelper.ScrollableHeightProviderForTesting = null;
                    WheelScrollHelper.VerticalOffsetProviderForTesting = null;
                }
            });
        }

        [Fact]
        public void ZeroDeltaOrAlreadyHandled_DoesNothing()
        {
            RunInSta(() =>
            {
                var rootScrollViewer = new ScrollViewer();
                bool callbackInvoked = false;
                WheelScrollHelper.OnScrolledForTesting = (_, _) => callbackInvoked = true;

                try
                {
                    // 1. Zero delta
                    var zeroArgs = CreateWheelArgs(0, rootScrollViewer);
                    WheelScrollHelper.ProcessMouseWheel(rootScrollViewer, zeroArgs);
                    Assert.False(zeroArgs.Handled);
                    Assert.False(callbackInvoked);

                    // 2. Already handled
                    var handledArgs = CreateWheelArgs(-120, rootScrollViewer);
                    handledArgs.Handled = true;
                    WheelScrollHelper.ProcessMouseWheel(rootScrollViewer, handledArgs);
                    Assert.False(callbackInvoked);
                }
                finally
                {
                    WheelScrollHelper.OnScrolledForTesting = null;
                }
            });
        }
    }
}
