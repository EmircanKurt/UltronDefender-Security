namespace AegisPC.Core.Enums
{
    /// <summary>
    /// Tarama oturumunun anlık yaşam döngüsü durumları.
    /// </summary>
    public enum ScanState
    {
        /// <summary>
        /// Tarayıcı boşta, herhangi bir tarama çalışmıyor.
        /// </summary>
        Idle = 0,

        /// <summary>
        /// Tarama aktif olarak çalışıyor ve dosyalar taranıyor.
        /// </summary>
        Scanning = 1,

        /// <summary>
        /// Tarama kullanıcı veya sistem tarafından duraklatıldı, dosya işleme bekletiliyor.
        /// </summary>
        Paused = 2,

        /// <summary>
        /// İptal talebi alındı; kuyruk işçileri ve işlemler durduruluyor.
        /// </summary>
        Cancelling = 3,

        /// <summary>
        /// Tarama başarıyla iptal edildi ve işçiler tamamen sonlandırıldı.
        /// </summary>
        Cancelled = 4,

        /// <summary>
        /// Tarama tüm hedefleri tarayarak normal şekilde tamamlandı.
        /// </summary>
        Completed = 5,

        /// <summary>
        /// Tarama kritik bir hata sebebiyle sonlandı.
        /// </summary>
        Failed = 6
    }
}
