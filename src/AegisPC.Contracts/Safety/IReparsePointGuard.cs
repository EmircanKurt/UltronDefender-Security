namespace AegisPC.Contracts.Safety
{
    /// <summary>
    /// Sembolik bağlar (Symlinks) ve NTFS Kavşak Noktalarını (Junctions) denetleyen,
    /// antivirüsün korunan sistem dosyalarını yanlışlıkla silmesini engelleyen güvenlik muhafızı.
    /// </summary>
    public interface IReparsePointGuard
    {
        /// <summary>
        /// Yolun bir reparse point (symlink veya junction) olup olmadığını ve hedefini analiz eder.
        /// </summary>
        ReparsePointInfo Inspect(string path);

        /// <summary>
        /// Bir sembolik bağı, hedefine zarar vermeden yalnızca bağın kendisini güvenle siler.
        /// </summary>
        bool SafeDeleteLinkOnly(string linkPath);
    }
}
