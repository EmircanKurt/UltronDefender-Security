using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels;

/// <summary>Separates a light-theme custom-folder draft from explicitly starting the existing manual scan flow.</summary>
public partial class ScanViewModel
{
    /// <summary>Holds a user-selected draft path only in memory; selecting it does not start analysis or persist private paths.</summary>
    [ObservableProperty] private string selectedCustomFolder = string.Empty;

    /// <summary>Opens the native folder picker without executing a scan; cancellation retains the previous draft.</summary>
    [RelayCommand]
    public void SelectCustomFolder()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog();
        if (dialog.ShowDialog() == true) SelectedCustomFolder = dialog.FolderName;
    }

    /// <summary>Starts the chosen custom path through the existing resource/ownership workflow, or requests a path when absent.</summary>
    [RelayCommand]
    public Task StartSelectedCustomScanAsync() => string.IsNullOrWhiteSpace(SelectedCustomFolder)
        ? StartCustomScanAsync() : StartCustomPathScanAsync(SelectedCustomFolder);
}
