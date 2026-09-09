using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AegisPC.Core.Helpers;

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
        /// Yürütülemez saf veri, medya, ses, 3D model, yazı tipi ve önbellek uzantıları.
        /// Tarama sırasında mikro-saniyeler içinde atlanarak CPU ve disk I/O tüketimini sıfıra indirir.
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
            "Package Cache",
            "AegisPC_BrowserStress_Tests",
            "AegisPC_Staging",
            "AegisPC_App",
            "AegisPC_App_Optimized",
            "AegisPC",
            "UltronDefender"
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

                // 2. ProgramData / AppData / ProgramFiles sistem kurulum ve veri dizinleri
                string[] specialFolders = {
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), // ProgramData
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),  // AppData\Local
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),       // AppData\Roaming
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),          // Program Files
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)       // Program Files (x86)
                };

                string[] subNames = { "UltronDefender", "AegisPC", "Ultron Defender Total Security", "Ultron Defender Security" };

                foreach (var sf in specialFolders)
                {
                    if (string.IsNullOrEmpty(sf)) continue;
                    foreach (var name in subNames)
                    {
                        paths.Add(Path.Combine(sf, name).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);
                    }
                }

                // 3. Geliştirme, Repository ve Staging Dizinleri
                string? searchRoot = baseDir;
                for (int i = 0; i < 6 && !string.IsNullOrEmpty(searchRoot); i++)
                {
                    if (File.Exists(Path.Combine(searchRoot, "AegisPC.sln")) ||
                        File.Exists(Path.Combine(searchRoot, "UltronDefender.sln")) ||
                        Directory.Exists(Path.Combine(searchRoot, ".git")))
                    {
                        paths.Add(searchRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);
                        break;
                    }
                    searchRoot = Path.GetDirectoryName(searchRoot);
                }

                string? curDir = Directory.GetCurrentDirectory();
                for (int i = 0; i < 6 && !string.IsNullOrEmpty(curDir); i++)
                {
                    if (File.Exists(Path.Combine(curDir, "AegisPC.sln")) ||
                        File.Exists(Path.Combine(curDir, "UltronDefender.sln")) ||
                        Directory.Exists(Path.Combine(curDir, ".git")))
                    {
                        paths.Add(curDir.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);
                        break;
                    }
                    curDir = Path.GetDirectoryName(curDir);
                }

                // Documents altındaki bilinen proje çalışma alanı
                string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                if (!string.IsNullOrEmpty(docs))
                {
                    paths.Add(Path.Combine(docs, "gemini virüs program").TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);
                }
            }
            catch { }
            return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        });

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
                // 1. Dosya adı denetimi: Ultron Defender veya AegisPC'ye ait hiçbir ikili/sembol/ayar taranmaz
                string fileName = Path.GetFileName(filePath);
                if (fileName.StartsWith("AegisPC", StringComparison.OrdinalIgnoreCase) ||
                    fileName.StartsWith("UltronDefender", StringComparison.OrdinalIgnoreCase) ||
                    fileName.StartsWith("Ultron.", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // 2. Özel sistem uygulama veri ve kurulum yolları (ProgramData, AppData, Program Files altındaki meşru klasörler ve repo/staging)
                if (filePath.Contains(@"\AppData\Local\AegisPC\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Contains(@"\AppData\Roaming\AegisPC\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Contains(@"\AppData\Local\UltronDefender\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Contains(@"\AppData\Roaming\UltronDefender\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Contains(@"\ProgramData\UltronDefender\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Contains(@"\ProgramData\AegisPC\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Contains(@"\Program Files\UltronDefender\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Contains(@"\Program Files (x86)\UltronDefender\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Contains(@"\AegisPC_Staging\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Contains(@"\AegisPC_App\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Contains(@"\AegisPC_App_Optimized\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Contains(@"\gemini virüs program\", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // 3. Derleyici sembolü ve hata ayıklama dosyaları (.pdb, .idb, .ilk, .exp, .lib)
                string ext = Path.GetExtension(filePath);
                if (!string.IsNullOrEmpty(ext) && (ext.Equals(".pdb", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".idb", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".ilk", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".exp", StringComparison.OrdinalIgnoreCase)))
                {
                    if (fileName.Contains("Aegis", StringComparison.OrdinalIgnoreCase) ||
                        fileName.Contains("Ultron", StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                // 4. Hariç tutulan tam dizin yolları
                foreach (var excludedPath in SelfExcludedPaths.Value)
                {
                    if (filePath.StartsWith(excludedPath, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch { }

            return false;
        }

        /// <summary>
        /// Content-Over-Extension: Dosyanın uzantısına veya ilk baytlarındaki PE/Arşiv sihirli baytlarına ("MZ", "PK", vb.) bakarak incelenebilirliğini doğrular.
        /// Güvenli medya ve belge dosyalarını atlayarak gereksiz CPU/Disk harcamasını önler.
        /// </summary>
        /// <param name="filePath">İncelenecek dosyanın tam yolu.</param>
        /// <returns>Dosya taranmaya uygun bir aday ise true; aksi halde false.</returns>
        public static bool IsInspectableCandidate(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;

            try
            {
                // 0. Öz-koruma: Uygulamanın kendi dizinleri ve ikilileri asla aday olamaz
                if (IsSelfOwnedPath(filePath)) return false;

                if (!File.Exists(filePath)) return false;

                string ext = Path.GetExtension(filePath).ToLowerInvariant();
                
                // 1. Bilinen güvenli medya, ofis, sembol ve belge uzantılarını doğrudan atla (CPU/RAM harcamaz)
                bool safeExtension = !string.IsNullOrEmpty(ext) && SafeMediaExtensions.Contains(ext);
                if (safeExtension) return false;

                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length == 0) return false;

                // 3. Yürütülebilir veya komut dosyası uzantısı ise doğrudan adaydır.
                if (!safeExtension && !string.IsNullOrEmpty(ext) && KnownCandidateExtensions.Contains(ext))
                {
                    return true;
                }

                // 5. Sihirli Bayt (Magic Byte) Denetimi: PE ("MZ"), ZIP ("PK"), 7z, RAR, Shebang ("#!")
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 16);
                Span<byte> header = stackalloc byte[4];
                int read = fs.Read(header);

                if (read >= 2)
                {
                    // MZ (Portable Executable - Windows PE32 / PE64 / DLL / SYS)
                    if (header[0] == 0x4D && header[1] == 0x5A) return true;

                    // PK (ZIP, JAR, APK, OpenXML)
                    if (header[0] == 0x50 && header[1] == 0x4B) return true;

                    // Shebang (#!) script
                    if (header[0] == 0x23 && header[1] == 0x21) return true;

                    if (read >= 4)
                    {
                        // 7z (37 7A BC AF)
                        if (header[0] == 0x37 && header[1] == 0x7A && header[2] == 0xBC && header[3] == 0xAF) return true;

                        // RAR (52 61 72 21)
                        if (header[0] == 0x52 && header[1] == 0x61 && header[2] == 0x72 && header[3] == 0x21) return true;
                    }
                }
            }
            catch
            {
                return false;
            }

            return false;
        }
    }
}
