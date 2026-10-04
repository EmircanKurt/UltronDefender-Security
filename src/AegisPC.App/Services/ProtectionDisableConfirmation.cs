using System;
using System.Threading.Tasks;
using System.Windows;

namespace AegisPC.App.Services;

/// <summary>Requests explicit consent without changing protection; closing the dialog means refusal.</summary>
public interface IProtectionDisableConfirmation
{
    /// <summary>Returns true only for an explicit Yes; absent UI or a dismissed dialog returns false.</summary>
    Task<bool> ConfirmAsync(string title, string message);
}

/// <summary>Uses an owner-bound warning dialog with No selected by default; never records input globally.</summary>
public sealed class ProtectionDisableConfirmation : IProtectionDisableConfirmation
{
    /// <inheritdoc />
    public Task<bool> ConfirmAsync(string title, string message)
    {
        var application = Application.Current;
        if (application?.Dispatcher == null || application.Dispatcher.HasShutdownStarted)
            return Task.FromResult(false);
        return application.Dispatcher.InvokeAsync(() =>
        {
            var owner = application.MainWindow;
            var result = owner?.IsVisible == true
                ? MessageBox.Show(owner, message, title, MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No)
                : MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            return result == MessageBoxResult.Yes;
        }).Task;
    }
}
