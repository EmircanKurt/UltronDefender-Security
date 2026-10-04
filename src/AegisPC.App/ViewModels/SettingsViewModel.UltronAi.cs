using System;
using System.Threading.Tasks;
using AegisPC.App.Services;
using AegisPC.ServiceContracts.IpcMessages;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels;

public partial class SettingsViewModel
{
    private readonly IProtectionDisableConfirmation _disableConfirmation;

    /// <summary>Displayed preference or fresh service observation for optional local AI review, not Guardian protection.</summary>
    [ObservableProperty] private bool isUltronAiEnabled = true;

    /// <summary>Whether a fresh service explicitly reported this optional module; legacy service fields remain unknown.</summary>
    [ObservableProperty] private bool isUltronAiStatusVerified;

    /// <summary>Separates optional review configuration from independent emergency protection, which remains unavailable.</summary>
    [ObservableProperty] private string ultronAiStatusText = "Hizmet durumu doğrulanmadı; bağımsız Guardian koruması henüz bağlı değil.";

    private void UpdateUltronAiObservation()
    {
        IsUltronAiStatusVerified = IsProtectionStatusVerified && _lastProtectionStatus?.IsUltronAiEnabled.HasValue == true;
        if (IsUltronAiStatusVerified)
        {
            IsUltronAiEnabled = _lastProtectionStatus!.IsUltronAiEnabled!.Value;
            if (_settingsService != null && _settingsService.Current.IsUltronAiEnabled != IsUltronAiEnabled)
            {
                _settingsService.Current.IsUltronAiEnabled = IsUltronAiEnabled;
                AegisPC.Security.DetectionPolicyRevision.Invalidate();
            }
        }
        UltronAiStatusText = !IsUltronAiStatusVerified
            ? "AI incelemesi doğrulanmadı. Hizmet bağlantısını ve uygulama/hizmet sürümünü kontrol edin."
            : IsUltronAiEnabled
                ? "Yerel dosya incelemesi açık. Bağımsız Guardian/acil müdahale henüz bağlı değil."
                : "AI incelemesi kapalı; bu katmanın ek değerlendirmesi yapılmaz. Diğer kalkanlar ayrı çalışır.";
    }

    /// <summary>Changes only optional AI review after service verification; disabling requires two separate explicit approvals.</summary>
    [RelayCommand]
    private async Task ToggleUltronAiAsync()
    {
        await _serviceProtectionCommandGate.WaitAsync();
        try
        {
            if (_settingsDisposed) return;
            await RequestServiceStatusAsync();
            UpdateUltronAiObservation();
            if (!IsUltronAiStatusVerified)
            {
                StatusMessage = "Ultron AI ayarı değiştirilmedi: güncel ve uyumlu hizmet yanıtı gerekli. Durumu Yenile düğmesini kullanın.";
                return;
            }
            bool enabled = !IsUltronAiEnabled;
            if (!enabled && !await ConfirmUltronAiDisableAsync())
            {
                StatusMessage = "Ultron AI kapatma iptal edildi; hizmete kapatma isteği gönderilmedi.";
                return;
            }
            if (_settingsDisposed) return;
            StatusMessage = "Ultron AI isteği hizmette doğrulanıyor; mevcut gözlenen durum korunuyor.";
            var status = await ServiceProtectionStatusPolicy.RequestUltronAiChangeAsync(_ipcClient, enabled);
            if (_settingsDisposed) return;
            ApplyServiceStatus(status);
            StatusMessage = enabled ? "Ultron AI yerel incelemesinin açık olduğu hizmette doğrulandı."
                : "Ultron AI yerel incelemesi kapatıldı. Ek analiz azalır; diğer kalkanlar ve Defender ayrıca kontrol edilmelidir.";
            if (_settingsService != null)
            {
                try { await _settingsService.SaveAsync(); }
                catch (Exception exception)
                {
                    Serilog.Log.Warning(exception, "Acknowledged AI preference could not be saved in the local snapshot");
                    StatusMessage += " Yerel tercih kaydedilemedi; sonraki açılışta hizmet durumu yeniden alınmalıdır.";
                }
            }
            await LogAuditAsync("Ultron AI yerel inceleme", enabled ? "Hizmette açık doğrulandı" : "İki kullanıcı onayıyla hizmette kapalı doğrulandı");
        }
        catch (Exception exception)
        {
            Serilog.Log.Warning(exception, "Optional AI review change was not acknowledged");
            if (!_settingsDisposed)
            {
                await RequestServiceStatusAsync();
                StatusMessage = "Ultron AI değişikliği doğrulanamadı; hizmet bağlantısını ve yönetici yetkisini kontrol edin. İstek uygulanmış olabilir.";
            }
        }
        finally
        {
            if (!_settingsDisposed)
            {
                UpdateUltronAiObservation();
                EvaluateProtectionWarning();
            }
            _serviceProtectionCommandGate.Release();
        }
    }

    private async Task<bool> ConfirmUltronAiDisableAsync()
    {
        if (!await _disableConfirmation.ConfirmAsync("Ultron AI kapatılsın mı? — 1/2",
            "Ultron AI kapatılırsa ek yerel dosya incelemesi durur. Şüpheli içerikler bu katmanda değerlendirilmez ve bazı tehditler fark edilmeyebilir. Bu işlem diğer Ultron kalkanlarını veya Windows Defender'ı kapatmaz. Devam etmek istiyor musunuz?"))
            return false;
        return await _disableConfirmation.ConfirmAsync("Son onay — 2/2",
            "Ultron AI incelemesini kapatmayı gerçekten onaylıyor musunuz? Bu katmanın değerlendirmesi yeniden açana kadar duracak. İptal etmek için Hayır'ı seçin.");
    }

    /// <summary>Requests a fresh authenticated service snapshot without starting a local protection engine.</summary>
    [RelayCommand]
    private async Task RefreshProtectionStatusAsync()
    {
        await RequestServiceStatusAsync();
        if (!_settingsDisposed)
        {
            UpdateUltronAiObservation();
            EvaluateProtectionWarning();
        }
    }
}
