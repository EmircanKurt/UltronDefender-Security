using System.Text.Json;
using AegisPC.Core.Models;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.Service.IPC;

public partial class NamedPipeServer
{
    private readonly TimedFileProtectionPause _fileProtectionPause;
    private sealed record PauseRequest(int Minutes, bool ResumeOnServiceStart);

    private async Task SavePauseIntentAsync(ProtectionPauseState? state)
    {
        var previous = _settingsService.Current.FileProtectionPause;
        _settingsService.Current.FileProtectionPause = state;
        try { await _settingsService.SaveAsync().ConfigureAwait(false); }
        catch { _settingsService.Current.FileProtectionPause = previous; throw; }
    }

    private async Task ProcessPauseAsync(ServiceCommand command, PipeClientConnection client)
    {
        var request = JsonSerializer.Deserialize<PauseRequest>(command.Payload ?? string.Empty)
            ?? throw new InvalidOperationException("Missing pause request.");
        await _fileProtectionPause.PauseAsync(request.Minutes, request.ResumeOnServiceStart).ConfigureAwait(false);
        await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus(command.RequestId))}").ConfigureAwait(false);
    }
}
