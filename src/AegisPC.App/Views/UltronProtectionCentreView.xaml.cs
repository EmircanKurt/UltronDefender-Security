using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views;

/// <summary>Displays local protection evidence without a chat, native mutations or automatic reboot.</summary>
public partial class UltronProtectionCentreView : Page
{
    /// <summary>Connects a read-only model and refreshes actual health on page entry.</summary>
    public UltronProtectionCentreView(UltronProtectionCentreViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        Loaded += async (_, _) => await viewModel.RefreshAsync();
    }
}
