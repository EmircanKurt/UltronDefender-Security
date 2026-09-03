using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using AegisPC.Core.Models;

namespace AegisPC.App.ViewModels
{
    /// <summary>
    /// ScanViewModel'in tehdit istihbaratı analizi, enfeksiyon vektörü sınıflandırması
    /// ve dosya metin önizlemesi işlemlerini yöneten partial parçası.
    /// </summary>
    public partial class ScanViewModel
    {
        /// <summary>
        /// Kullanıcı sonuç listesinden yeni bir bulgu seçtiğinde tetiklenerek tehdit analizini
        /// ve dosya metin önizlemesini günceller.
        /// </summary>
        /// <param name="value">Seçilen yeni güvenlik bulgusu veya seçim kaldırıldıysa null.</param>
        partial void OnSelectedFindingChanged(SecurityFinding? value)
        {
            HasSelectedFinding = value != null;
            if (value != null)
            {
                ComputeThreatIntelligence(value);
                LoadTextPreview(value.ObjectPath);
            }
            else
            {
                HasTextPreview = false;
                TextPreviewContent = string.Empty;
                TextPreviewLineCount = string.Empty;
                IsTextFile = false;
            }
        }

        /// <summary>
        /// Seçili dosyanın metin tabanlı olup olmadığını doğrular ve güvenli şekilde ilk 500 satırını okur.
        /// </summary>
        /// <param name="filePath">Önizlenecek dosyanın tam yolu.</param>
        private void LoadTextPreview(string? filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                HasTextPreview = false;
                TextPreviewContent = string.Empty;
                TextPreviewLineCount = string.Empty;
                IsTextFile = false;
                return;
            }

            try
            {
                var ext = Path.GetExtension(filePath).ToLowerInvariant();
                var textExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    ".txt", ".log", ".ini", ".cfg", ".xml", ".json", ".csv", ".md", ".inf",
                    ".htm", ".html", ".lua", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".py",
                    ".c", ".cpp", ".h", ".cs", ".sql", ".sh", ".yml", ".yaml", ".conf", ".nfo"
                };

                IsTextFile = textExtensions.Contains(ext);

                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(fs, Encoding.UTF8);

                var sb = new StringBuilder();
                int lineCount = 0;
                string? line;
                while ((line = reader.ReadLine()) != null && lineCount < 500)
                {
                    lineCount++;
                    sb.AppendLine($"{lineCount,4} | {line}");
                }

                if (lineCount > 0)
                {
                    TextPreviewContent = sb.ToString();
                    TextPreviewLineCount = $"{lineCount} satır metin incelendi" + (lineCount >= 500 ? " (İlk 500 satır sınırı)" : "");
                    HasTextPreview = true;
                }
                else
                {
                    TextPreviewContent = "(Dosya boş / Metin içeriği bulunamadı)";
                    TextPreviewLineCount = "0 satır";
                    HasTextPreview = true;
                }
            }
            catch (Exception ex)
            {
                TextPreviewContent = $"[Önizleme okunamadı: {ex.Message}]";
                TextPreviewLineCount = "Hata";
                HasTextPreview = true;
            }
        }

        /// <summary>
        /// Güvenlik bulgusunun başlık ve açıklama verilerini inceleyerek tehdit kategorisini,
        /// olası bulaşma kaynağını ve kullanıcıya önerilen müdahale adımlarını üretir.
        /// </summary>
        /// <param name="f">İncelenecek güvenlik bulgusu.</param>
        private void ComputeThreatIntelligence(SecurityFinding f)
        {
            var title = (f.Title ?? "").ToLowerInvariant();
            var desc = (f.Description ?? "").ToLowerInvariant();

            if (title.Contains("keylog") || desc.Contains("keylog") || desc.Contains("klavye"))
            {
                SelectedThreatCategory = "⌨️ Keylogger (Klavye ve Şifre Dinleyici)";
                SelectedInfectionVector = "Korsan yazılımlar, sahte crack programları veya kimlik avı e-posta ekleri.";
                SelectedRemediationAdvice = "1. Dosyayı derhal Karantina Kasasına kilitleyin.\n2. Bankacılık ve e-posta parolalarınızı sıfırlayın.";
            }
            else if (title.Contains("ransom") || desc.Contains("ransom") || title.Contains("fidye"))
            {
                SelectedThreatCategory = "🔒 Fidye Yazılımı (Ransomware / Dosya Kilitleyici)";
                SelectedInfectionVector = "Güvensiz web sitelerinden indirilen dosyalar veya zararlı ofis makroları.";
                SelectedRemediationAdvice = "1. Dosyayı derhal Karantina Kasasına kilitleyin.\n2. Fidye Kalkanı'nın devrede olduğundan emin olun.";
            }
            else if (title.Contains("trojan") || desc.Contains("trojan") || desc.Contains("truva"))
            {
                SelectedThreatCategory = "🐎 Truva Atı (Trojan.Downloader / Arka Kapı)";
                SelectedInfectionVector = "Meşru bir program gibi kamufle edilmiş kurulum dosyaları.";
                SelectedRemediationAdvice = "1. Dosyayı Karantina Kasasına kilitleyin.\n2. Tam sistem taraması gerçekleştirin.";
            }
            else
            {
                SelectedThreatCategory = "⚠️ Şüpheli Kod / İstenmeyen Yazılım (PUP / RiskWare)";
                SelectedInfectionVector = "İnternetten indirilen üçüncü parti kurulum paketleri veya geçici dosyalar.";
                SelectedRemediationAdvice = "1. Dosyayı Karantina Kasasına kilitleyin.";
            }
        }
    }
}
