using System.Threading.Tasks;

namespace AegisPC.Contracts.Services;

public interface INotificationService
{
    Task ShowInfoAsync(string title, string message);
    Task ShowWarningAsync(string title, string message);
    Task ShowErrorAsync(string title, string message);
    Task<bool> ShowConfirmationAsync(string title, string message);
}
