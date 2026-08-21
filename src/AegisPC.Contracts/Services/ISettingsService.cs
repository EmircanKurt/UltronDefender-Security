using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services;

public interface ISettingsService
{
    T? GetSetting<T>(string key, T defaultValue);
    void SetSetting<T>(string key, T value);
    Task SaveAsync(CancellationToken cancellationToken = default);
    Task LoadAsync(CancellationToken cancellationToken = default);
}
