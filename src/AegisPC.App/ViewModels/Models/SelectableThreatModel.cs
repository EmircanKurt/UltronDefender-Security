using CommunityToolkit.Mvvm.ComponentModel;
using AegisPC.Core.Models;

namespace AegisPC.App.ViewModels
{
    /// <summary>
    /// Tarama sonuç listesinde yer alan ve kullanıcının tek tek veya topluca
    /// seçerek karantinaya alabileceği tehdit öğesini temsil eden Observable model.
    /// </summary>
    public partial class SelectableThreatModel : ObservableObject
    {
        /// <summary>
        /// Tehdit öğesinin kullanıcı tarafından seçilip seçilmediğini belirtir.
        /// </summary>
        [ObservableProperty]
        private bool isSelected = true;

        /// <summary>
        /// Tehdit dosyasının adı.
        /// </summary>
        [ObservableProperty]
        private string name = string.Empty;

        /// <summary>
        /// Tehdidin sınıflandırma türü (örneğin: Kötücül Yazılım, Truva Atı, RiskWare).
        /// </summary>
        [ObservableProperty]
        private string threatType = "Kötücül Yazılım";

        /// <summary>
        /// Tehdit nesnesinin dosya sistemi veya süreç türü (örneğin: Dosya, Bellek / Yürütülebilir).
        /// </summary>
        [ObservableProperty]
        private string objectType = "Dosya";

        /// <summary>
        /// Tehdit dosyasının disk üzerindeki tam yolu.
        /// </summary>
        [ObservableProperty]
        private string location = string.Empty;

        /// <summary>
        /// Bu UI modelinin temsil ettiği temel güvenlik bulgusu veri nesnesi.
        /// </summary>
        public SecurityFinding Finding { get; set; } = new();
    }
}
