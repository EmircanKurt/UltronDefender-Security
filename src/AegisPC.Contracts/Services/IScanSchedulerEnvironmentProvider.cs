namespace AegisPC.Contracts.Services
{
    /// <summary>
    /// Tarama Zamanlayıcısı 2.0 için donanım ve oturum ortam koşullarını (pil, tam ekran oyun, disk IOPS) sorgulayan arayüz.
    /// </summary>
    public interface IScanSchedulerEnvironmentProvider
    {
        /// <summary>
        /// Cihazın şarjda değil, pil gücünde çalışıp çalışmadığını bildirir.
        /// </summary>
        bool IsRunningOnBattery();

        /// <summary>
        /// Kullanıcının tam ekran oyun veya sunum modunda olup olmadığını denetler.
        /// </summary>
        bool IsFullscreenOrGameActive();

        /// <summary>
        /// Anlık disk etkinlik oranını (% 0-100) döner.
        /// </summary>
        double GetDiskActivityPercentage();
    }
}
