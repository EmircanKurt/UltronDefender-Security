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

        public SettingsService(string? settingsFilePath = null)
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            _settingsFilePath = !string.IsNullOrWhiteSpace(settingsFilePath)
                ? Path.GetFullPath(settingsFilePath)
                : Path.Combine(appData, "AegisPC", "settings.json");
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
                _currentSettings = await TryLoadAsync(_settingsFilePath, cancellationToken)
                    ?? await TryLoadAsync(_settingsFilePath + ".bak", cancellationToken)
                    ?? new AppSettings();
                ValidateSettings(_currentSettings);
            }
            finally
            {
                _semaphore.Release();
            }
        }

        public async Task SaveAsync(CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            string? temporaryPath = null;
            try
            {
                ValidateSettings(_currentSettings);

                var directory = Path.GetDirectoryName(_settingsFilePath);
                if (directory != null && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                temporaryPath = _settingsFilePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                await using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write,
                    FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    await JsonSerializer.SerializeAsync(stream, _currentSettings,
                        new JsonSerializerOptions { WriteIndented = true }, cancellationToken);
                    await stream.FlushAsync(cancellationToken);
                    stream.Flush(flushToDisk: true);
                }

                cancellationToken.ThrowIfCancellationRequested();
                if (File.Exists(_settingsFilePath))
                    File.Replace(temporaryPath, _settingsFilePath, _settingsFilePath + ".bak");
                else
                    File.Move(temporaryPath, _settingsFilePath);
            }
            finally
            {
                try
                {
                    if (temporaryPath != null && File.Exists(temporaryPath)) File.Delete(temporaryPath);
                }
                finally { _semaphore.Release(); }
            }
        }

        private static async Task<AppSettings?> TryLoadAsync(string path, CancellationToken cancellationToken)
        {
            if (!File.Exists(path)) return null;
            try
            {
                var json = await File.ReadAllTextAsync(path, cancellationToken);
                return JsonSerializer.Deserialize<AppSettings>(json);
            }
            catch (JsonException ex)
            {
                System.Diagnostics.Trace.TraceWarning("Invalid settings JSON at {0}: {1}", path, ex.Message);
                return null;
            }
        }

        private void ValidateSettings(AppSettings settings)
        {
            if (settings.PerformanceSampleIntervalMs < 500)
            {
                settings.PerformanceSampleIntervalMs = 500;
            }
            if (settings.DataRetentionDays < 1)
            {
                settings.DataRetentionDays = 1;
            }
            if (settings.AutoQuarantineThreshold < 0)
            {
                settings.AutoQuarantineThreshold = 0;
            }
            else if (settings.AutoQuarantineThreshold > 100)
            {
                settings.AutoQuarantineThreshold = 100;
            }
            settings.ScheduledScanHour = Math.Clamp(settings.ScheduledScanHour, 0, 23);
            settings.ScheduledScanIntervalHours = Math.Clamp(settings.ScheduledScanIntervalHours, 0, 24);
            settings.IdleScanThresholdMinutes = Math.Clamp(settings.IdleScanThresholdMinutes, 1, 240);
            settings.IdleScanIntervalHours = Math.Clamp(settings.IdleScanIntervalHours, 1, 168);
            if (!Enum.IsDefined(settings.ScanResourceMode))
                settings.ScanResourceMode = AegisPC.Core.Enums.ScanResourceMode.Auto;
            if (settings.LastManualScanResourceMode is { } manualMode && !Enum.IsDefined(manualMode))
                settings.LastManualScanResourceMode = null;
            // Existing installations stored a remembered manual choice in the scheduled/global mode.
            // Capture it once in the new field so later scheduled-profile edits cannot overwrite it.
            if (settings.RememberScanResourceMode && settings.LastManualScanResourceMode == null)
                settings.LastManualScanResourceMode = settings.ScanResourceMode;
            settings.DismissedIncidentIds ??= new();
        }
    }
}
