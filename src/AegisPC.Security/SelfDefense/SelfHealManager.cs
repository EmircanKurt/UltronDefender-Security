using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace AegisPC.Security.SelfDefense
{
    /// <summary>
    /// Kendi kendini onarma ve eski haline getirme motoru (Self-Heal Mechanism).
    /// Müdahale sonucu devre dışı bırakılmak istenen servisleri, kayıt defteri anahtarlarını
    /// ve çekirdek sürücülerini anında algılayıp otomatik olarak yeniden ayağa kaldırır.
    /// </summary>
    public class SelfHealManager
    {
        private readonly ILogger<SelfHealManager>? _logger;
        public const string DefaultServiceName = "AegisPCProtectionService";
        public const string DefaultDriverName = "AegisFilter";

        public SelfHealManager(ILogger<SelfHealManager>? logger = null)
        {
            _logger = logger;
        }

        /// <summary>
        /// Devre dışı bırakılan veya durdurulan servisi otomatik olarak onarır ve başlatır.
        /// </summary>
        public bool HealService(string serviceName = DefaultServiceName)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return false;

            bool healed = false;
            try
            {
                // 1. Kayıt defterinde Start = 4 (Disabled) yapılmışsa Start = 2 (Automatic) yap
                string serviceKeyPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
                using (var key = Registry.LocalMachine.OpenSubKey(serviceKeyPath, writable: true))
                {
                    if (key != null)
                    {
                        var startVal = key.GetValue("Start");
                        if (startVal is int val && val == 4)
                        {
                            key.SetValue("Start", 2, RegistryValueKind.DWord);
                            _logger?.LogInformation("Anti-Tamper Self-Heal: {Service} servis başlangıç türü Automatic (2) olarak düzeltildi.", serviceName);
                            healed = true;
                        }
                    }
                }

                // 2. Servis başlangıç türünü garantiye al ve servisi başlat
                RunCommandLineUtility("sc.exe", $"config {serviceName} start= auto");
                bool started = RunCommandLineUtility("sc.exe", $"start {serviceName}");
                if (started)
                {
                    _logger?.LogInformation("Anti-Tamper Self-Heal: {Service} servisi yeniden başlatıldı.", serviceName);
                    healed = true;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Self-Heal servisi onarırken hata: {Service}", serviceName);
            }

            return healed;
        }

        /// <summary>
        /// Unload edilen minifilter sürücüsünü sisteme yeniden yükler (fltmc load).
        /// </summary>
        public bool HealMinifilterDriver(string driverName = DefaultDriverName)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return false;

            try
            {
                _logger?.LogWarning("Anti-Tamper Self-Heal: {Driver} minifilter sürücüsü yeniden yükleniyor...", driverName);
                bool success = RunCommandLineUtility("fltmc.exe", $"load {driverName}");
                return success;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Minifilter sürücüsü yüklenemedi: {Driver}", driverName);
                return false;
            }
        }

        /// <summary>
        /// Silinmeye çalışılan veya değiştirilen kritik kayıt defteri değerini aslına döndürür.
        /// </summary>
        public bool HealRegistryValue(string subKeyPath, string valueName, object correctValue, RegistryValueKind kind = RegistryValueKind.DWord)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return false;

            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(subKeyPath, writable: true);
                if (key != null)
                {
                    key.SetValue(valueName, correctValue, kind);
                    _logger?.LogInformation("Anti-Tamper Self-Heal: HKLM\\{Key}\\{Val} değeri onarıldı.", subKeyPath, valueName);
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Kayıt defteri onarılamadı: {Key}", subKeyPath);
            }

            return false;
        }

        private static bool RunCommandLineUtility(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var proc = Process.Start(psi);
                if (proc != null)
                {
                    proc.WaitForExit(3000);
                    return proc.ExitCode == 0;
                }
            }
            catch { }
            return false;
        }
    }
}
