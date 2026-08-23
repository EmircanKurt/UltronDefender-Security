using System;

namespace AegisPC.Core.Configuration
{
    /// <summary>
    /// Ultron Defender Total Security modül ve özellik bayrakları için merkezi kaynak.
    /// Tüm View ve ViewModel'ler özelliklerin aktiflik durumunu bu kaynaktan alır.
    /// </summary>
    public static class FeatureFlags
    {
        /// <summary>
        /// Ağ, DNS ve Web Kalkanı modülü devrede mi?
        /// </summary>
        public static bool IsNetworkShieldActive { get; set; } = true;

        /// <summary>
        /// Fidye Yazılımı İyileştirme ve Canlı Tuzak Kalkanı devrede mi?
        /// </summary>
        public static bool IsRansomwareShieldActive { get; set; } = true;

        /// <summary>
        /// Oyuncu & Crack Koruma Kalkanı (GameCrackWatchdog) devrede mi?
        /// </summary>
        public static bool IsGamerCrackShieldActive { get; set; } = true;

        /// <summary>
        /// Bulut tabanlı tehdit sorgulama altyapısı devrede mi?
        /// </summary>
        public static bool IsCloudLookupActive { get; set; } = false;

        /// <summary>
        /// Gelişmiş EDR Tehdit & Olay Merkezi devrede mi?
        /// </summary>
        public static bool IsIncidentCenterActive { get; set; } = true;
    }
}
