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
        /// Product-state roots used solely to prevent destructive actions against application data.
        /// Membership does not establish ownership, a clean verdict, or a scan exclusion.
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
        /// Reports whether a path lies under a product-state root for destructive-action safety.
        /// User-writable files beneath these roots are not trusted and must still be inspected.
        /// </summary>
        /// <param name="filePath">Path to evaluate without opening or trusting its content.</param>
        /// <returns>True for a protected root member; never a clean-file verdict.</returns>
        public static bool IsSelfOwnedPath(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;

            try
            {
                // Root membership is only a destructive-action guard. It cannot prove that an
                // arbitrary file beneath a writable root belongs to the product.
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
        /// Queues every nonempty path, including files beneath product-state roots.
        /// A filename, extension, or directory cannot establish a clean verdict.
        /// </summary>
        /// <param name="filePath">Candidate path; content is inspected by a later worker.</param>
        /// <returns>True for any nonempty candidate path.</returns>
        public static bool IsInspectableCandidate(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;

            return true;
        }
    }
}
