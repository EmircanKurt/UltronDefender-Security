using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using AegisPC.Core.Enums;

namespace AegisPC.App.Controls;

/// <summary>Presentational scan chooser; it binds existing commands but never starts scans during selection or construction.</summary>
public partial class ClassicScanSurface : UserControl
{
    /// <summary>Retains the selected scope across theme changes, independently of engine resource settings.</summary>
    public ScanType SelectedScanType { get; private set; } = ScanType.Quick;

    /// <summary>Initializes local controls and width-dependent layout without security services, timers or global input hooks.</summary>
    public ClassicScanSurface()
    {
        InitializeComponent();
        BindSelectedCommand();
        SizeChanged += (_, _) => ArrangeRows();
    }

    private void OnChoiceChecked(object sender, RoutedEventArgs e)
    {
        if (sender is not RadioButton radio || !Enum.TryParse(radio.Tag as string, out ScanType type)) return;
        SelectedScanType = type;
        if (StartSelectedButton == null) return;
        BindSelectedCommand();
        ScopeTitle.Text = type switch { ScanType.Full => "Yerel diskler", ScanType.Custom => "Seçilen hedef", _ => "İndirilenler" };
        ScopeDescription.Text = type switch
        {
            ScanType.Full => "Ön incelemeden sonra erişilebilir sabit disklerdeki dosyalar incelenir.",
            ScanType.Custom => "Yalnız seçtiğiniz dosya veya klasör taranır.",
            _ => "Son 7 günde eklenen veya değişen indirme, masaüstü ve geçici dosyalar incelenir."
        };
        SecondaryScopeTitle.Text = type == ScanType.Custom ? "Hedef sınırı" : "Başlangıç konumları";
        SecondaryScopeDescription.Text = type == ScanType.Custom
            ? "Klasör seç düğmesi hedefi değiştirir; seçmek taramayı başlatmaz."
            : "Aktif program/modül dosyaları ve başlangıç hedefleri incelenir; süreç belleği taranmaz.";
    }

    private void BindSelectedCommand()
    {
        string command = SelectedScanType switch
        {
            ScanType.Full => "StartFullScanCommand",
            ScanType.Custom => "StartSelectedCustomScanCommand",
            _ => "StartQuickScanCommand"
        };
        StartSelectedButton.SetBinding(Button.CommandProperty, new Binding(command));
        StartSelectedButton.Content = "Taramayı başlat";
    }

    private void OnFolderPickerClicked(object sender, RoutedEventArgs e) => CustomChoice.IsChecked = true;

    private void ArrangeRows()
    {
        bool compact = ActualWidth < 700;
        ChoiceColumn.Width = new GridLength(compact ? 1 : 1.35, GridUnitType.Star);
        ScopeColumn.Width = compact ? new GridLength(0) : new GridLength(1, GridUnitType.Star);
        Grid.SetColumn(ScopePanel, compact ? 0 : 1);
        Grid.SetRow(ScopePanel, compact ? 1 : 0);
        SelectionPanel.Margin = compact ? new Thickness(0, 0, 0, 12) : new Thickness(0, 0, 8, 0);
        bool narrow = ActualWidth < 420;
        Grid.SetColumn(FolderPickerButton, narrow ? 0 : 1);
        Grid.SetRow(FolderPickerButton, narrow ? 1 : 0);
        Grid.SetColumnSpan(StartSelectedButton, narrow ? 2 : 1);
        Grid.SetColumnSpan(FolderPickerButton, narrow ? 2 : 1);
        StartSelectedButton.Margin = narrow ? new Thickness(0, 0, 0, 10) : new Thickness(0, 0, 10, 0);
    }
}
