using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AegisPC.Contracts.Safety;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Safety
{
    /// <summary>
    /// Windows işletim sistemi çekirdek yapılarını, sistem kayıtlarını, sürücülerini ve
    /// antivirüsün kendi dosyalarını kazara silinme veya karantinaya alınmaya karşı koruyan derin muhafız.
    /// </summary>
    public class ProtectedPathGuard : IProtectedPathGuard
    {
        private readonly ICanonicalPathResolver _pathResolver;
        private readonly ILogger<ProtectedPathGuard>? _logger;

        private readonly string _windowsDir;
        private readonly string _system32Dir;
        private readonly string _driversDir;
        private readonly string _configDir;
        private readonly string _winSxSDir;
        private readonly string _aegisAppDataDir;

        private static readonly HashSet<string> CriticalCoreBinaries = new(StringComparer.OrdinalIgnoreCase)
        {
            "ntoskrnl.exe", "hal.dll", "ci.dll", "winload.exe", "winload.efi", "bootmgr",
            "csrss.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe", "smss.exe"
        };

        private static readonly HashSet<string> CriticalDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "ntfs.sys", "fltmgr.sys", "tcpip.sys", "ksecdd.sys", "cng.sys", "mountmgr.sys", "disk.sys", "volmgr.sys"
        };

        private static readonly HashSet<string> RegistryHiveNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "SAM", "SYSTEM", "SECURITY", "SOFTWARE", "DEFAULT", "DRIVERS", "COMPONENTS", "BBI"
        };

        public ProtectedPathGuard(
            ICanonicalPathResolver? pathResolver = null,
            ILogger<ProtectedPathGuard>? logger = null)
        {
            _pathResolver = pathResolver ?? new CanonicalPathResolver();
            _logger = logger;

            _windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            _system32Dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            _driversDir = Path.Combine(_system32Dir, "drivers");
            _configDir = Path.Combine(_system32Dir, "config");
            _winSxSDir = Path.Combine(_windowsDir, "WinSxS");

            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            _aegisAppDataDir = Path.Combine(appData, "AegisPC");
        }

        public bool IsProtected(string path)
        {
            var eval = Evaluate(path);
            return eval.IsProtected;
        }

        public bool IsCriticalSystemCore(string path)
        {
            var eval = Evaluate(path);
            return eval.IsCriticalSystemCore;
        }

        public ProtectedPathEvaluation Evaluate(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return new ProtectedPathEvaluation
                {
                    OriginalPath = path,
                    IsProtected = false,
                    Reason = "Geçersiz veya boş dosya yolu."
                };
            }

            var canonical = _pathResolver.Resolve(path);
            var fileName = Path.GetFileName(canonical);

            // 1. Registry Hives (SAM, SYSTEM, SECURITY, SOFTWARE...)
            if (canonical.StartsWith(_configDir, StringComparison.OrdinalIgnoreCase))
            {
                if (RegistryHiveNames.Contains(fileName) || fileName.StartsWith("SAM.", StringComparison.OrdinalIgnoreCase) || fileName.StartsWith("SYSTEM.", StringComparison.OrdinalIgnoreCase))
                {
                    return new ProtectedPathEvaluation
                    {
                        OriginalPath = path,
                        CanonicalPath = canonical,
                        IsProtected = true,
                        IsCriticalSystemCore = true,
                        Category = ProtectedPathCategory.WindowsRegistryHives,
                        Reason = $"Windows Sistem Kayıt Defteri Çekirdek Kovanı ({fileName}) silinemez veya karantinaya alınamaz."
                    };
                }
            }

            // 2. Windows Kernel & Boot Core (ntoskrnl, hal.dll, csrss, lsass, winlogon...)
            if (CriticalCoreBinaries.Contains(fileName) && canonical.StartsWith(_windowsDir, StringComparison.OrdinalIgnoreCase))
            {
                return new ProtectedPathEvaluation
                {
                    OriginalPath = path,
                    CanonicalPath = canonical,
                    IsProtected = true,
                    IsCriticalSystemCore = true,
                    Category = ProtectedPathCategory.WindowsKernelAndBoot,
                    Reason = $"Kritik Windows Çekirdek / Önyükleme Bileşeni ({fileName}) korumalıdır."
                };
            }

            // 3. Kritik Dosya Sistemi & Çekirdek Sürücüleri
            if (CriticalDrivers.Contains(fileName) && canonical.StartsWith(_driversDir, StringComparison.OrdinalIgnoreCase))
            {
                return new ProtectedPathEvaluation
                {
                    OriginalPath = path,
                    CanonicalPath = canonical,
                    IsProtected = true,
                    IsCriticalSystemCore = true,
                    Category = ProtectedPathCategory.WindowsDrivers,
                    Reason = $"Kritik Windows Çekirdek Sürücüsü ({fileName}) korumalıdır."
                };
            }

            // 4. Windows Component Store (WinSxS)
            if (canonical.StartsWith(_winSxSDir, StringComparison.OrdinalIgnoreCase))
            {
                return new ProtectedPathEvaluation
                {
                    OriginalPath = path,
                    CanonicalPath = canonical,
                    IsProtected = true,
                    IsCriticalSystemCore = false,
                    Category = ProtectedPathCategory.WindowsComponentStoreWinSxS,
                    Reason = "Windows Bileşen Deposu (WinSxS) korumalıdır."
                };
            }

            // 5. System Volume Information
            if (canonical.Contains(@"\System Volume Information", StringComparison.OrdinalIgnoreCase))
            {
                return new ProtectedPathEvaluation
                {
                    OriginalPath = path,
                    CanonicalPath = canonical,
                    IsProtected = true,
                    IsCriticalSystemCore = true,
                    Category = ProtectedPathCategory.WindowsSystemVolumeInformation,
                    Reason = "Windows Sistem Birim Bilgisi (System Volume Information) korumalıdır."
                };
            }

            // 6. AegisPC / Ultron Defender Self-Protection (Yalnızca kritik çekirdek ikilileri ve anahtar dosyaları)
            if (canonical.StartsWith(_aegisAppDataDir, StringComparison.OrdinalIgnoreCase))
            {
                var ext = Path.GetExtension(canonical).ToLowerInvariant();
                if (ext is ".exe" or ".dll" or ".sys" || fileName.Equals("vault.key", StringComparison.OrdinalIgnoreCase))
                {
                    return new ProtectedPathEvaluation
                    {
                        OriginalPath = path,
                        CanonicalPath = canonical,
                        IsProtected = true,
                        IsCriticalSystemCore = false,
                        Category = ProtectedPathCategory.AegisSecuritySelfProtection,
                        Reason = "AegisPC Öz-Koruma (Self-Protection) aktif."
                    };
                }
            }

            // Korunan yol değil
            return new ProtectedPathEvaluation
            {
                OriginalPath = path,
                CanonicalPath = canonical,
                IsProtected = false,
                IsCriticalSystemCore = false,
                Category = ProtectedPathCategory.None,
                Reason = "Korumasız kullanıcı / uygulama alanı."
            };
        }
    }
}
