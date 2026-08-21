using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;

namespace AegisPC.Infrastructure.Configuration
{
    /// <summary>
    /// Service for managing application settings.
    /// </summary>
    public class SettingsService : ISettingsService
    {
        private readonly string _settingsFilePath;
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);
        private AppSettings _currentSettings;

        public SettingsService()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            _settingsFilePath = Path.Combine(appData, "AegisPC", "settings.json");
            _currentSettings = new AppSettings();
        }

        public AppSettings Current => _currentSettings;

        public T? GetSetting<T>(string key, T defaultValue)
        {
            var prop = typeof(AppSettings).GetProperty(key);
            if (prop == null) return defaultValue;
            var val = prop.GetValue(_currentSettings);
            if (val is T typedVal) return typedVal;
            return defaultValue;
        }

        public void SetSetting<T>(string key, T value)
        {
            var prop = typeof(AppSettings).GetProperty(key);
            if (prop != null && prop.CanWrite)
            {
                prop.SetValue(_currentSettings, value);
            }
        }

        public async Task LoadAsync(CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                if (!File.Exists(_settingsFilePath))
                {
                    _currentSettings = new AppSettings();
                    return;
                }

                var json = await File.ReadAllTextAsync(_settingsFilePath, cancellationToken);
                _currentSettings = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
            }
            finally
            {
                _semaphore.Release();
            }
        }

        public async Task SaveAsync(CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                ValidateSettings(_currentSettings);

                var directory = Path.GetDirectoryName(_settingsFilePath);
                if (directory != null && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var json = JsonSerializer.Serialize(_currentSettings, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_settingsFilePath, json, cancellationToken);
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private void ValidateSettings(AppSettings settings)
        {
            if (settings.PerformanceSampleIntervalMs < 500)
            {
                settings.PerformanceSampleIntervalMs = 500;
            }
            if (settings.MaxScanConcurrency < 1)
            {
                settings.MaxScanConcurrency = 1;
            }
            if (settings.DataRetentionDays < 1)
            {
                settings.DataRetentionDays = 1;
            }
        }
    }
}
