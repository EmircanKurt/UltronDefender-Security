using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;

namespace AegisPC.Core.Localization
{
    public interface ILocalizationService
    {
        string CurrentLanguage { get; }
        void SetLanguage(string cultureCode);
        string GetString(string key, string? defaultValue = null);
        string this[string key] { get; }
        event Action<string>? LanguageChanged;
    }

    public class LocalizationService : ILocalizationService
    {
        private static readonly Lazy<LocalizationService> _instance = new(() => new LocalizationService());
        public static LocalizationService Instance => _instance.Value;

        private string _currentCulture = "tr-TR";
        private readonly ConcurrentDictionary<string, Dictionary<string, string>> _dictionaries = new(StringComparer.OrdinalIgnoreCase);

        public string CurrentLanguage => _currentCulture;
        public event Action<string>? LanguageChanged;

        public LocalizationService()
        {
            InitializeDictionaries();
            var sysCulture = CultureInfo.CurrentUICulture.Name;
            _currentCulture = sysCulture.StartsWith("en", StringComparison.OrdinalIgnoreCase) ? "en-US" : "tr-TR";
        }

        private void InitializeDictionaries()
        {
            var tr = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["AppTitle"] = "Ultron Defender Total Security",
                ["Dashboard_Protected"] = "Sisteminiz Guvende",
                ["Dashboard_ThreatsFound"] = "Aktif Tehditler Mevcut",
                ["Scan_Quick"] = "Hizli Tarama",
                ["Scan_Full"] = "Tam Sistem Taramasi",
                ["Scan_Custom"] = "Ozel Tarama",
                ["Scan_Status_Ready"] = "Taramaya hazir.",
                ["Scan_Status_Scanning"] = "Tarama devam ediyor...",
                ["Scan_Status_Completed"] = "Tarama tamamlandi.",
                ["Quarantine_Title"] = "Karantina Kasasi",
                ["Quarantine_Empty"] = "Karantina kasasinda tecrit edilmis dosya bulunmuyor.",
                ["Settings_General"] = "Genel Ayarlar",
                ["Settings_RealTime"] = "Gercek Zamanli Koruma",
                ["Settings_Language"] = "Dil / Language",
                ["Common_OK"] = "Tamam",
                ["Common_Cancel"] = "Iptal",
                ["Common_Delete"] = "Sil",
                ["Common_Restore"] = "Geri Yukle"
            };

            var en = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["AppTitle"] = "Ultron Defender Total Security",
                ["Dashboard_Protected"] = "System Protected",
                ["Dashboard_ThreatsFound"] = "Active Threats Detected",
                ["Scan_Quick"] = "Quick Scan",
                ["Scan_Full"] = "Full System Scan",
                ["Scan_Custom"] = "Custom Scan",
                ["Scan_Status_Ready"] = "Ready to scan.",
                ["Scan_Status_Scanning"] = "Scan in progress...",
                ["Scan_Status_Completed"] = "Scan completed.",
                ["Quarantine_Title"] = "Quarantine Vault",
                ["Quarantine_Empty"] = "No quarantined files in vault.",
                ["Settings_General"] = "General Settings",
                ["Settings_RealTime"] = "Real-Time Protection",
                ["Settings_Language"] = "Language / Dil",
                ["Common_OK"] = "OK",
                ["Common_Cancel"] = "Cancel",
                ["Common_Delete"] = "Delete",
                ["Common_Restore"] = "Restore"
            };

            _dictionaries["tr-TR"] = tr;
            _dictionaries["tr"] = tr;
            _dictionaries["en-US"] = en;
            _dictionaries["en"] = en;
        }

        public void SetLanguage(string cultureCode)
        {
            if (string.IsNullOrWhiteSpace(cultureCode)) return;
            _currentCulture = cultureCode;
            LanguageChanged?.Invoke(_currentCulture);
        }

        public string GetString(string key, string? defaultValue = null)
        {
            if (_dictionaries.TryGetValue(_currentCulture, out var dict) && dict.TryGetValue(key, out var val))
            {
                return val;
            }

            if (_dictionaries.TryGetValue("tr-TR", out var trDict) && trDict.TryGetValue(key, out var trVal))
            {
                return trVal;
            }

            return defaultValue ?? key;
        }

        public string this[string key] => GetString(key);
    }
}
