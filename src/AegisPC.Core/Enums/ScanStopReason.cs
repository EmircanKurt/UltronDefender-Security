namespace AegisPC.Core.Enums
{
    /// <summary>
    /// Taramanın sonlanma veya durdurulma nedeni.
    /// </summary>
    public enum ScanStopReason
    {
        /// <summary>
        /// Henüz bir durma nedeni yok (boşta veya çalışıyor).
        /// </summary>
        None = 0,

        /// <summary>
        /// Tarama tüm hedefleri tarayarak olağan şekilde tamamlandı.
        /// </summary>
        CompletedNormally = 1,

        /// <summary>
        /// Kullanıcı tarafından manuel olarak iptal edildi.
        /// </summary>
        UserCancelled = 2,

        /// <summary>
        /// Tarama zaman aşımına uğradı.
        /// </summary>
        Timeout = 3,

        /// <summary>
        /// Sistem kapanması veya servis durması sebebiyle sonlandırıldı.
        /// </summary>
        SystemShutdown = 4,

        /// <summary>
        /// Beklenmeyen bir hata veya istisna sebebiyle durdu.
        /// </summary>
        Error = 5
    }
}
