using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using AegisPC.App.Services;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.RealTime;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace AegisPC.App.ViewModels
{
    public partial class RansomwareShieldViewModel : ObservableObject
    {
        private readonly IRansomwareProtectionEngine? _ransomwareEngine;
        private readonly SettingsService? _settingsService;
        private readonly IWindowsToastNotificationService? _toastService;

        [ObservableProperty]
        private bool _isShieldEnabled = true;

        [ObservableProperty]
        private ObservableCollection<ProtectedFolder> _protectedFolders = new();

        [ObservableProperty]
        private ObservableCollection<RansomwareEvent> _recentEvents = new();

        [ObservableProperty]
        private string _shieldStatusText = "Fidye Kalkanı Aktif (Tuzaklar ve İzleme Devrede)";

        [ObservableProperty]
        private string _toggleButtonText = "Kalkanı Kapat";

        [ObservableProperty]
        private int _canaryFileCount = 8;

        [ObservableProperty]
        private int _protectedFolderCount = 4;

        public RansomwareShieldViewModel(
            IRansomwareProtectionEngine? ransomwareEngine = null,
            SettingsService? settingsService = null,
            IWindowsToastNotificationService? toastService = null)
        {
            _ransomwareEngine = ransomwareEngine;
            _settingsService = settingsService;
            _toastService = toastService;

            InitializeFolders();

            if (_settingsService != null)
            {
                IsShieldEnabled = _settingsService.Current.IsRansomwareShieldEnabled;
            }
            else if (_ransomwareEngine != null)
            {
                IsShieldEnabled = _ransomwareEngine.IsShieldActive;
            }

            UpdateStatusText();

            if (_ransomwareEngine != null)
            {
                _ransomwareEngine.OnRansomwareAttemptDetected += OnRansomwareDetected;
                if (IsShieldEnabled && !_ransomwareEngine.IsShieldActive)
                {
                    _ransomwareEngine.StartShield();
                }
                CanaryFileCount = _ransomwareEngine.CanaryFileCount;
            }
        }

        private void UpdateStatusText()
        {
            if (!IsShieldEnabled)
            {
                ShieldStatusText = "Fidye Kalkanı Devre Dışı";
                ToggleButtonText = "Kalkanı Etkinleştir";
            }
            else if (ProtectedFolderCount == 0 && CanaryFileCount == 0)
            {
                ShieldStatusText = "Kalkan Hazır — Henüz Korumalı Klasör veya Yem Eklenmedi";
                ToggleButtonText = "Kalkanı Devre Dışı Bırak";
            }
            else
            {
                ShieldStatusText = $"Fidye Kalkanı Aktif ({ProtectedFolderCount} Klasör, {CanaryFileCount} Tuzak Devrede)";
                ToggleButtonText = "Kalkanı Devre Dışı Bırak";
            }
        }

        [ObservableProperty]
        private ObservableCollection<AllowedRansomwareApplication> _allowedApplications = new();

        [ObservableProperty]
        private int _totalBlockedCount;

        private void InitializeFolders()
        {
            if (_ransomwareEngine != null)
            {
                var dirs = _ransomwareEngine.ProtectedDirectories;
                var list = dirs.Select(d => new ProtectedFolder
                {
                    Name = new DirectoryInfo(d).Name,
                    Path = d,
                    IsProtected = true,
                    SizeBytes = 0
                }).ToList();

                ProtectedFolders = new ObservableCollection<ProtectedFolder>(list);
                ProtectedFolderCount = ProtectedFolders.Count;

                var apps = _ransomwareEngine.AllowedApplications;
                AllowedApplications = new ObservableCollection<AllowedRansomwareApplication>(apps);
                TotalBlockedCount = _ransomwareEngine.TotalBlockedAttempts;
            }
            else
            {
                var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var folders = new[]
                {
                    new ProtectedFolder { Name = "Belgeler", Path = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), IsProtected = true, SizeBytes = 1024L * 1024 * 500 },
                    new ProtectedFolder { Name = "Masaüstü", Path = Environment.GetFolderPath(Environment.SpecialFolder.Desktop), IsProtected = true, SizeBytes = 1024L * 1024 * 100 },
                    new ProtectedFolder { Name = "Resimler", Path = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures), IsProtected = true, SizeBytes = 1024L * 1024 * 1200 },
                    new ProtectedFolder { Name = "Videolar", Path = Environment.GetFolderPath(Environment.SpecialFolder.MyVideos), IsProtected = true, SizeBytes = 1024L * 1024 * 2500 }
                }.Where(f => Directory.Exists(f.Path));

                ProtectedFolders = new ObservableCollection<ProtectedFolder>(folders);
                ProtectedFolderCount = ProtectedFolders.Count;
            }
        }

        private void OnRansomwareDetected(object? sender, RansomwareAlertEventArgs e)
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                TotalBlockedCount++;
                RecentEvents.Insert(0, new RansomwareEvent
                {
                    Timestamp = e.Timestamp,
                    ProcessName = !string.IsNullOrEmpty(e.OffendingProcessName) ? e.OffendingProcessName : "Şüpheli Süreç / İhlal",
                    FilePath = e.OffendingFilePath,
                    Action = e.ProcessTerminated ? "Süreç Durduruldu ve Engellendi" : "Erişim Engellendi"
                });

                _toastService?.ShowToast(
                    e.ProcessTerminated ? "🛑 Fidye Saldırısı Durduruldu!" : "⚠️ Korunan Klasör İhlali Engellendi!",
                    $"{e.DetectionReason} (Dosya: '{Path.GetFileName(e.OffendingFilePath)}')",
                    e.ProcessTerminated ? "Error" : "Warning");
            });
        }

        [RelayCommand]
        private void ToggleShield()
        {
            IsShieldEnabled = !IsShieldEnabled;
            UpdateStatusText();

            if (IsShieldEnabled)
            {
                _ransomwareEngine?.StartShield();
                _toastService?.ShowToast("🛡️ Fidye Kalkanı Devrede", "Otomatik tuzak dosyalar ve Controlled Folder Access izleme aktif edildi.", "Success");
            }
            else
            {
                _ransomwareEngine?.StopShield();
                _toastService?.ShowToast("⚠️ Fidye Kalkanı Kapatıldı", "Fidye yazılımı ve izinsiz şifreleme koruması devre dışı bırakıldı.", "Warning");
            }

            if (_settingsService != null)
            {
                _settingsService.Current.IsRansomwareShieldEnabled = IsShieldEnabled;
                _ = _settingsService.SaveAsync();
            }
        }

        [RelayCommand]
        private void AddFolder()
        {
            var dialog = new OpenFolderDialog
            {
                Title = "Korunacak Klasörü Seçin"
            };

            if (dialog.ShowDialog() == true)
            {
                ProtectedFolders.Add(new ProtectedFolder
                {
                    Name = new DirectoryInfo(dialog.FolderName).Name,
                    Path = dialog.FolderName,
                    IsProtected = true,
                    SizeBytes = 0
                });
                ProtectedFolderCount = ProtectedFolders.Count;
                _ransomwareEngine?.AddProtectedDirectory(dialog.FolderName);
            }
        }

        [RelayCommand]
        private void RemoveFolder(ProtectedFolder folder)
        {
            if (folder != null)
            {
                ProtectedFolders.Remove(folder);
                ProtectedFolderCount = ProtectedFolders.Count;
                _ransomwareEngine?.RemoveProtectedDirectory(folder.Path);
            }
        }

        [RelayCommand]
        private void AddAllowedApp()
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Güvenilir Uygulama Seçin (.exe)",
                Filter = "Çalıştırılabilir Dosyalar (*.exe)|*.exe|Tüm Dosyalar (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                var exePath = dialog.FileName;
                var appName = Path.GetFileNameWithoutExtension(exePath);

                if (!AllowedApplications.Any(a => a.ExecutablePath.Equals(exePath, StringComparison.OrdinalIgnoreCase)))
                {
                    var app = new AllowedRansomwareApplication
                    {
                        ExecutablePath = exePath,
                        ApplicationName = appName,
                        Publisher = "Kullanıcı Tarafından Eklendi",
                        IsSigned = false,
                        IsSystemWhitelisted = false,
                        AddedAt = DateTime.UtcNow
                    };

                    AllowedApplications.Add(app);
                    _ransomwareEngine?.AddAllowedApplication(exePath, appName);
                    _toastService?.ShowToast("✅ Uygulamaya İzin Verildi", $"'{appName}' korunan klasörlerde yazma erişimi için güvenilir listeye eklendi.", "Success");
                }
            }
        }

        [RelayCommand]
        private void RemoveAllowedApp(AllowedRansomwareApplication app)
        {
            if (app != null)
            {
                AllowedApplications.Remove(app);
                _ransomwareEngine?.RemoveAllowedApplication(app.ExecutablePath);
                _toastService?.ShowToast("⚠️ İzin Kaldırıldı", $"'{app.ApplicationName}' güvenilir listeden çıkarıldı.", "Info");
            }
        }
    }

    public class ProtectedFolder
    {
        public string Path { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public bool IsProtected { get; set; }
        public long SizeBytes { get; set; }
    }

    public class RansomwareEvent
    {
        public DateTime Timestamp { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
    }
}
