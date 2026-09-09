using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using AegisPC.Core.Enums;

namespace AegisPC.App.Views
{
    /// <summary>
    /// Tarama başlangıcında kullanıcıya kaynak kullanım profilini (Sakin / Dengeli / Tam Güç) soran diyalog penceresi.
    /// </summary>
    public partial class ScanResourceSelectionDialog : Window
    {
        public ScanResourceMode SelectedMode { get; private set; } = ScanResourceMode.Balanced;
        public bool RememberChoice => ChkRemember.IsChecked == true;

        public ScanResourceSelectionDialog(ScanResourceMode initialMode = ScanResourceMode.Balanced)
        {
            InitializeComponent();

            SelectedMode = (initialMode == ScanResourceMode.Auto || initialMode == ScanResourceMode.VeryLow)
                ? ScanResourceMode.Balanced
                : initialMode;

            UpdateUiForMode(SelectedMode);

            long totalRam = (long)GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
            if (totalRam <= 0) totalRam = 8L * 1024 * 1024 * 1024;
            long totalGb = (long)Math.Round((double)totalRam / (1024.0 * 1024.0 * 1024.0));
            if (totalGb < 1) totalGb = 1;

            TxtSystemRamInfo.Text = $"Sisteminizde {totalGb} GB RAM algılandı. Uygun kaynak profilini seçin:";
            TxtLowDesc.Text = $"~1 GB RAM, düşük CPU • ({totalGb} GB RAM'in ~1 GB'ı kullanılabilir • Günlük işleri aksatmaz)";
            TxtBalancedDesc.Text = $"RAM'in yarısı • ({totalGb} GB RAM'in ~{Math.Max(1, totalGb / 2)} GB'ı kullanılabilir • Hızlı ve dengeli)";
            TxtMaximumDesc.Text = $"Tüm çekirdekler • ({totalGb} GB RAM'in ~{Math.Max(1, (long)(totalGb * 0.75))} GB'ı kullanılabilir • Maksimum güç)";
        }

        private void UpdateUiForMode(ScanResourceMode mode)
        {
            SelectedMode = mode;
            RbLow.IsChecked = (mode == ScanResourceMode.Low || mode == ScanResourceMode.VeryLow);
            RbBalanced.IsChecked = (mode == ScanResourceMode.Balanced);
            RbMaximum.IsChecked = (mode == ScanResourceMode.Maximum || mode == ScanResourceMode.High);

            UpdateBorderHighlights();
        }

        private void UpdateBorderHighlights()
        {
            try
            {
                var activeBrush = (Brush)FindResource("BrushBrandPrimary");
                var inactiveBrush = (Brush)FindResource("BrushCardBorder");

                BorderLow.BorderBrush = RbLow.IsChecked == true ? activeBrush : inactiveBrush;
                BorderBalanced.BorderBrush = RbBalanced.IsChecked == true ? activeBrush : inactiveBrush;
                BorderMaximum.BorderBrush = RbMaximum.IsChecked == true ? activeBrush : inactiveBrush;

                BorderLow.BorderThickness = new Thickness(RbLow.IsChecked == true ? 1.5 : 1.0);
                BorderBalanced.BorderThickness = new Thickness(RbBalanced.IsChecked == true ? 1.5 : 1.0);
                BorderMaximum.BorderThickness = new Thickness(RbMaximum.IsChecked == true ? 1.5 : 1.0);
            }
            catch { }
        }

        private void OnSelectLow(object sender, MouseButtonEventArgs e)
        {
            UpdateUiForMode(ScanResourceMode.Low);
        }

        private void OnSelectBalanced(object sender, MouseButtonEventArgs e)
        {
            UpdateUiForMode(ScanResourceMode.Balanced);
        }

        private void OnSelectMaximum(object sender, MouseButtonEventArgs e)
        {
            UpdateUiForMode(ScanResourceMode.Maximum);
        }

        private void OnRadioClicked(object sender, RoutedEventArgs e)
        {
            if (RbLow.IsChecked == true) SelectedMode = ScanResourceMode.Low;
            else if (RbMaximum.IsChecked == true) SelectedMode = ScanResourceMode.Maximum;
            else SelectedMode = ScanResourceMode.Balanced;

            UpdateBorderHighlights();
        }

        private void OnStartClicked(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        private void OnCancelClicked(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
