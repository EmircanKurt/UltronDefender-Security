using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Fidye virüsü tuzak (canary) dosyalarını yöneten bileşen arayüzü.
    /// </summary>
    public interface ICanaryTrapManager
    {
        /// <summary>
        /// Disk üzerinde konuşlandırılmış aktif canary tuzak dosyası sayısı.
        /// </summary>
        int CanaryFileCount { get; }

        /// <summary>
        /// Şu anda tuzak dosyaları temizleniyor mu bayrağı (false alarm önlemek için).
        /// </summary>
        bool IsCleaningUpCanaries { get; }

        /// <summary>
        /// Aktif tuzak dosyalarının yolları.
        /// </summary>
        IReadOnlyList<string> CanaryFiles { get; }

        /// <summary>
        /// Belirtilen korumalı klasörlerde canary tuzak dosyalarını oluşturur veya gizler.
        /// </summary>
        void DeployCanaries(IEnumerable<string> protectedDirs);

        /// <summary>
        /// Korumalı klasörlerdeki tüm canary tuzak dosyalarını güvenle siler.
        /// </summary>
        void CleanupCanaries();

        /// <summary>
        /// Belirtilen dosya yolunun bir canary tuzak dosyası olup olmadığını kontrol eder.
        /// </summary>
        bool IsCanaryPath(string path);
    }

    /// <summary>
    /// Korumalı kullanıcı klasörlerinde alfabetik olarak ilk sıralara yerleşen gizli tuzak dosyalarını
    /// oluşturan, durumunu izleyen ve kalkan kapandığında güvenle temizleyen yönetici.
    /// </summary>
    public class CanaryTrapManager : ICanaryTrapManager
    {
        public const string CanaryFileName = "!_ultron_shield_canary.docx";

        private const string CanaryDecoyContent =
@"🛡️ ULTRON DEFENDER TOTAL SECURITY — GİZLİ GÜVENLİK VE FİDYE KORUMA AJANI (CANARY DECOY)
========================================================================================
Sayın Kullanıcı,

Bu dosya, bilgisayarınızı fidye virüslerine (Ransomware / WannaCry / LockBit vb.) karşı
7/24 korumak için Ultron Defender tarafından özel olarak oluşturulmuş bir güvenlik tuzağıdır.

🎯 AMACIMIZ:
Olası bir fidye virüsü dosyalarınızı şifrelemeye başladığında, alfabetik sırayla ilk bu
dosyayı hedef alır. Bu dosyaya dokunulduğu an Ultron Defender virüsü 0.1 milisaniyede yakalar
ve gerçek fotoğraflarınız, belgeleriniz ve oyunlarınız zarar görmeden virüsü durdurur.

⚠️ BİLGİLENDİRME:
Amacımız bilgisayarınızı korumaktır. Bilgisayarınızın maksimum güvenliği için bu dosyanın
silinmemesi ve kalması önerilir. Ultron Defender devrede olduğu sürece güvendesiniz!";

        private readonly List<string> _canaryFiles = new();
        private volatile bool _isCleaningUpCanaries;
        private readonly object _lock = new();

        public int CanaryFileCount
        {
            get { lock (_lock) return _canaryFiles.Count; }
        }

        public bool IsCleaningUpCanaries => _isCleaningUpCanaries;

        public IReadOnlyList<string> CanaryFiles
        {
            get { lock (_lock) return _canaryFiles.ToList(); }
        }

        public void DeployCanaries(IEnumerable<string> protectedDirs)
        {
            lock (_lock)
            {
                _canaryFiles.Clear();
                foreach (var dir in protectedDirs)
                {
                    try
                    {
                        if (!Directory.Exists(dir)) continue;

                        var canaryPath = Path.Combine(dir, CanaryFileName);
                        if (!File.Exists(canaryPath))
                        {
                            File.WriteAllText(canaryPath, CanaryDecoyContent, Encoding.UTF8);
                            File.SetAttributes(canaryPath, FileAttributes.Hidden | FileAttributes.System);
                        }
                        else
                        {
                            File.SetAttributes(canaryPath, FileAttributes.Hidden | FileAttributes.System);
                        }
                        _canaryFiles.Add(canaryPath);
                    }
                    catch { }
                }
            }
        }

        public void CleanupCanaries()
        {
            _isCleaningUpCanaries = true;
            try
            {
                lock (_lock)
                {
                    foreach (var canary in _canaryFiles.ToList())
                    {
                        try
                        {
                            if (File.Exists(canary))
                            {
                                File.SetAttributes(canary, FileAttributes.Normal);
                                File.Delete(canary);
                            }
                        }
                        catch { }
                    }
                    _canaryFiles.Clear();
                }
            }
            finally
            {
                _isCleaningUpCanaries = false;
            }
        }

        public bool IsCanaryPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            return path.EndsWith(CanaryFileName, StringComparison.OrdinalIgnoreCase);
        }
    }
}
