namespace AegisPC.Contracts.Safety
{
    /// <summary>
    /// Windows dosya yollarını (8.3 kısa adlar, symlinkler, cihaz ön ekleri \\?\, göreli dizinler, ters/düz eğik çizgiler)
    /// deterministik ve mutlak fiziksel dosya yoluna dönüştüren kanonikleştirici arayüzü.
    /// </summary>
    public interface ICanonicalPathResolver
    {
        /// <summary>
        /// Dosya veya dizin yolunu tam kanonik fiziksel formatına çözer.
        /// </summary>
        string Resolve(string path);

        /// <summary>
        /// Verilen iki farklı yolun (örn. 8.3 vs Long path) fiziksel olarak aynı dosyayı gösterip göstermediğini doğrular.
        /// </summary>
        bool AreSamePhysicalFile(string path1, string path2);
    }
}
