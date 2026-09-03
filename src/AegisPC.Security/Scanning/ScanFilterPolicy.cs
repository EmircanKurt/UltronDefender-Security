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
            ".git",
            ".vs",
            ".cache",
            "node_modules",
            "Package Cache",
            "AegisPC_BrowserStress_Tests",
            "AegisLabSuite",
            // ── DEVELOPMENT & PACKAGE LIBRARIES (Geliştirici Kütüphane / Paket Önbellekleri) ──
            "site-packages",
            "dist-packages",
            ".venv",
            "venv",
            ".conda",
            "conda-meta",
            "pip-wheel-metadata",
            ".cargo",
            ".rustup",
            ".nuget",
            // ── SELF-PROTECTION: Uygulamanın kendi veri/imza/log dizinleri ve derleme çıktıları tarama dışı ──
            "UltronDefender",
            "Ultron Defender Total Security",
            "Ultron Defender",
            "AegisPC",
            "AegisPC_App",
            "bin",
            "obj",
            "Debug",
            "Release",
            "x64",
            "x86"
        };

        /// <summary>
        /// Uygulamanın kendi dizinlerini (ProgramData, ProgramFiles, AppData, BaseDirectory) içeren lazy yol koleksiyonu.
        /// </summary>
        public static readonly Lazy<string[]> SelfExcludedPaths = new(() =>
        {
            var paths = new List<string>();
            try
            {
                // %ProgramData%\UltronDefender & %ProgramData%\Ultron Defender Total Security
                string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                if (!string.IsNullOrEmpty(programData))
                {
                    paths.Add(Path.Combine(programData, "UltronDefender") + Path.DirectorySeparatorChar);
                    paths.Add(Path.Combine(programData, "Ultron Defender Total Security") + Path.DirectorySeparatorChar);
                    paths.Add(Path.Combine(programData, "AegisPC") + Path.DirectorySeparatorChar);
                }

                // %ProgramFiles%\Ultron Defender Total Security & %ProgramFiles%\UltronDefender
                string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                if (!string.IsNullOrEmpty(progFiles))
                {
                    paths.Add(Path.Combine(progFiles, "UltronDefender") + Path.DirectorySeparatorChar);
                    paths.Add(Path.Combine(progFiles, "Ultron Defender Total Security") + Path.DirectorySeparatorChar);
                    paths.Add(Path.Combine(progFiles, "AegisPC") + Path.DirectorySeparatorChar);
                }

                // %ProgramFiles(x86)%
                string progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                if (!string.IsNullOrEmpty(progFilesX86))
                {
                    paths.Add(Path.Combine(progFilesX86, "UltronDefender") + Path.DirectorySeparatorChar);
                    paths.Add(Path.Combine(progFilesX86, "Ultron Defender Total Security") + Path.DirectorySeparatorChar);
                    paths.Add(Path.Combine(progFilesX86, "AegisPC") + Path.DirectorySeparatorChar);
                }

                // %AppData%\AegisPC & %AppData%\UltronDefender
                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                if (!string.IsNullOrEmpty(appData))
                {
                    paths.Add(Path.Combine(appData, "AegisPC") + Path.DirectorySeparatorChar);
                    paths.Add(Path.Combine(appData, "UltronDefender") + Path.DirectorySeparatorChar);
                    paths.Add(Path.Combine(appData, "Ultron Defender Total Security") + Path.DirectorySeparatorChar);
                }

                // %LocalAppData%\AegisPC & %LocalAppData%\UltronDefender
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (!string.IsNullOrEmpty(localAppData))
                {
                    paths.Add(Path.Combine(localAppData, "AegisPC") + Path.DirectorySeparatorChar);
                    paths.Add(Path.Combine(localAppData, "UltronDefender") + Path.DirectorySeparatorChar);
                    paths.Add(Path.Combine(localAppData, "Ultron Defender Total Security") + Path.DirectorySeparatorChar);
                }

                // Uygulamanın kendi çalışma dizini (exe, dll'ler, pdb'ler, AppDomain BaseDirectory)
                string? processDir = Path.GetDirectoryName(Environment.ProcessPath);
                if (!string.IsNullOrEmpty(processDir))
                    paths.Add(processDir.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);

                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                if (!string.IsNullOrEmpty(baseDir))
                    paths.Add(baseDir.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);
            }
            catch { }
            return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        });

        /// <summary>
        /// Verilen dosya yolunun uygulamanın kendi veri/imza/log/config dizinlerinden
        /// birine ait olup olmadığını kontrol eder. True dönerse dosya taranmamalıdır.
        /// </summary>
        /// <param name="filePath">Kontrol edilecek dosya yolu.</param>
        /// <returns>Uygulamanın kendi dosyası ise true; aksi halde false.</returns>
        public static bool IsSelfOwnedPath(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;
            foreach (var excludedPath in SelfExcludedPaths.Value)
            {
                if (filePath.StartsWith(excludedPath, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
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
                if (!File.Exists(filePath)) return false;

                string ext = Path.GetExtension(filePath).ToLowerInvariant();
                
                // 1. Bilinen güvenli medya, ofis ve belge uzantılarını doğrudan atla (CPU/RAM harcamaz)
                if (!string.IsNullOrEmpty(ext) && SafeMediaExtensions.Contains(ext))
                {
                    return false;
                }

                // 2. Oyun ve Mod Klasörü Koruması: Oyun kaynakları (.zip, .bin, .dat, .pak, .dds, .dae) virüs değildir ve devasadır
                bool isGame = PathHelper.IsGameOrRepackDirectory(filePath) || GameCrackClassifier.IsGameCrackOrEmulator(filePath);
                if (isGame && (ext != ".exe" && ext != ".dll" && ext != ".scr" && ext != ".bat" && ext != ".cmd" && ext != ".ps1"))
                {
                    return false;
                }

                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length == 0) return false;

                // 3. 100 MB'dan büyük dosyaları tarama (Oyun repacki, büyük video, ISO, VM disk vb. CPU/RAM patlamasını önler)
                if (fileInfo.Length > 100 * 1024 * 1024)
                {
                    return false;
                }

                // 4. Yürütülebilir veya komut dosyası uzantısı ise doğrudan adaydır
                if (!string.IsNullOrEmpty(ext) && KnownCandidateExtensions.Contains(ext))
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
