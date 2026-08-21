using System.Threading.Tasks;
using System.Windows;
using AegisPC.Contracts.Services;

namespace AegisPC.App.Services
{
    public class NotificationService : INotificationService
    {
        public Task ShowInfoAsync(string title, string message)
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);
            });
            return Task.CompletedTask;
        }

        public Task ShowWarningAsync(string title, string message)
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Warning);
            });
            return Task.CompletedTask;
        }

        public Task ShowErrorAsync(string title, string message)
        {
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);
            });
            return Task.CompletedTask;
        }

        public Task<bool> ShowConfirmationAsync(string title, string message)
        {
            bool result = false;
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                var dialogResult = MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Question);
                result = (dialogResult == MessageBoxResult.Yes);
            });
            return Task.FromResult(result);
        }
    }
}
