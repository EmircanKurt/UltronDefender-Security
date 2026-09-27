using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AegisPC.Core.Helpers;
using Serilog;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Tarama motorunun dosya filtreleme, uzantı sınıflandırma, sihirli bayt (magic byte) denetimi,
    /// dizin hariç tutma ve kendi kendini koruma (self-exclusion) politikalarını yöneten merkezi sınıf.
    /// </summary>
    public static class ScanFilterPolicy
    {
        /// <summary>
        /// Zararlı yazılım taşıma potansiyeli olan yürütülebilir, betik ve arşiv uzantıları.
        /// </summary>
        public static readonly HashSet<string> KnownCandidateExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
            ".hta", ".jar", ".wsf", ".ws", ".wsh", ".cpl", ".msi", ".msc", ".reg", ".com", ".pif",
            ".drv", ".ocx", ".efi", ".zip", ".7z", ".rar", ".iso", ".img", ".tar", ".gz", ".cab",
            ".nupkg", ".apk", ".bin", ".dat", ".tmp"
        };

        /// <summary>
        /// Legacy file-type hints. These names do not establish trust or exclude files from scanning.
        /// </summary>
        public static readonly HashSet<string> SafeMediaExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            // Medya ve Ses Dosyaları (Yürütülemez Veri)
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tiff", ".tga", ".psd",
            ".mp3", ".wav", ".flac", ".ogg", ".aac", ".m4a", ".wma", ".opus", ".mid", ".midi",
            ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".flv", ".m4v", ".3gp",
            // Belgeler ve Yazı Tipleri
            ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".doc", ".xls", ".ppt",
            ".ttf", ".otf", ".woff", ".woff2", ".eot", ".fon",
            // 3D Modeller, Dokular ve Oyun Varlıkları (Tamamen veri / render dosyaları)
            ".dae", ".dds", ".obj", ".fbx", ".blend", ".3ds", ".max", ".gltf", ".glb", ".mtl", ".mat",
            ".prefab", ".asset", ".anim", ".mesh", ".unityweb", ".pck", ".bsp", ".wad", ".pak",
            ".pc", ".jbeam", ".cda", ".bik", ".bk2",
            // Metin, Yapılandırma ve Veri Dosyaları (Yürütülemez — 2 Milyon Dosyada Mikro-saniye Atlama)
            ".txt", ".log", ".ini", ".cfg", ".conf", ".config", ".xml", ".json", ".csv", ".tsv", ".md", ".inf",
            ".htm", ".html", ".css", ".scss", ".sass", ".less", ".map", ".sql", ".sqlite", ".db", ".db-shm",
            ".db-wal", ".yml", ".yaml", ".toml", ".properties", ".nfo", ".diz", ".mo", ".po", ".pot",
            ".cache", ".idx", ".dict", ".sub", ".srt", ".vtt", ".ass",
            // Program Hata Ayıklama Veritabanı ve Derleyici Çıktıları (.pdb — Asla taranmaz)
            ".pdb", ".idb", ".ilk", ".exp", ".lib",
            // Bilimsel Veri, Makine Öğrenimi ve Python Önbellek Dosyaları (Yürütülemez Veri Bloğu)
            ".fits", ".fit", ".fts", ".npy", ".npz", ".h5", ".hdf5", ".parquet", ".pkl", ".pickle",
            ".pyc", ".pyo", ".whl", ".whl.metadata", ".ipynb", ".rst", ".po", ".pot"
        };

        /// <summary>
        /// Tarama dışı tutulacak işletim sistemi servis dizinleri, paket kütüphaneleri ve uygulama dizinleri.
        /// </summary>
        public static readonly HashSet<string> ExcludedDirectoryNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "$Recycle.Bin",
            "System Volume Information",
            "WinSxS",
            "Servicing",
            "SoftwareDistribution",
            "assembly",
            "Microsoft.NET",
            "Installer",
            "DriverStore",
            "SystemApps",
            "Prefetch",
            "Panther",
            "rescache",
            "Fonts",
            "DeliveryOptimization",
            "$Windows.~BT",
            "$WinREAgent",
            "Config.Msi",
            "Recovery",
            "Package Cache"
        };

        /// <summary>
        /// Uygulamanın kendi dizinlerini (ProgramData, ProgramFiles, AppData, BaseDirectory, Repo) içeren lazy yol koleksiyonu.
        /// </summary>
        public static readonly Lazy<string[]> SelfExcludedPaths = new(() =>
        {
            var paths = new List<string>();
            try
            {
                // 1. Uygulamanın kendi çalışma dizini (exe, dll'ler, pdb'ler, AppDomain BaseDirectory)
                string? processDir = Path.GetDirectoryName(Environment.ProcessPath);
                if (!string.IsNullOrEmpty(processDir))
                    paths.Add(processDir.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);

                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                if (!string.IsNullOrEmpty(baseDir))
                    paths.Add(baseDir.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);

                // Only actual state roots are self-excluded; fictional installation names and
                // development repositories are not trusted directories.
                string[] specialFolders = {
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), // ProgramData
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),  // AppData\Local
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)       // AppData\Roaming
                };

                string[] subNames = { "UltronDefender", "AegisPC" };

                foreach (var sf in specialFolders)
                {
                    if (string.IsNullOrEmpty(sf)) continue;
                    foreach (var name in subNames)
                    {
                        paths.Add(Path.Combine(sf, name).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);
                    }
                }

            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to resolve self-excluded paths in ScanFilterPolicy");
            }
            return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        });

        /// <summary>
        /// Fidye kalkanına ait canary tuzak dosyalarını tespit eder.
        /// </summary>
        public static bool IsCanaryFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string fileName = Path.GetFileName(filePath);
            return fileName.Contains("_ultron_shield_canary", StringComparison.OrdinalIgnoreCase) ||
                   fileName.Contains("_ultron_canary", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Verilen dosya yolunun uygulamanın kendi veri/imza/log/config dizinlerinden
        /// veya bileşenlerinden birine ait olup olmadığını kontrol eder. True dönerse dosya asla taranmaz.
        /// </summary>
        /// <param name="filePath">Kontrol edilecek dosya yolu.</param>
        /// <returns>Uygulamanın kendi dosyası ise true; aksi halde false.</returns>
        public static bool IsSelfOwnedPath(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;

            try
            {
                // Öz-koruma yalnızca doğrulanmış ürün köklerinde uygulanır. Dosya adı veya yolun
                // herhangi bir yerindeki "AegisPC" metni güven sınırı değildir; aksi halde bir
                // saldırgan zararlı dosyayı yeniden adlandırarak taramayı atlayabilir.
                string canonicalPath = Path.GetFullPath(filePath);
                foreach (var excludedPath in SelfExcludedPaths.Value)
                {
                    if (canonicalPath.StartsWith(excludedPath, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Failed to check if path {FilePath} is self-owned", filePath);
            }

            return false;
        }

        /// <summary>
        /// Queues every non-product path. Extension, magic bytes and readability never establish a clean verdict.
        /// File opening and content verification happen in the bounded scan worker, not the producer.
        /// </summary>
        /// <param name="filePath">İncelenecek dosyanın tam yolu.</param>
        /// <returns>Dosya taranmaya uygun bir aday ise true; aksi halde false.</returns>
        public static bool IsInspectableCandidate(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;

            return !IsSelfOwnedPath(filePath);
        }
    }
}
