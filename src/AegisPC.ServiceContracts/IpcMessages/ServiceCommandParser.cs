using System.Text.Json;

namespace AegisPC.ServiceContracts.IpcMessages;

/// <summary>Validates the command envelope before enum defaults can become a privileged operation.</summary>
public static class ServiceCommandParser
{
    /// <summary>
    /// Accepts an explicit, defined numeric CommandType exactly once and an optional unique nonempty
    /// request identity; malformed, duplicate, oversized or unknown commands are never dispatched.
    /// </summary>
    public static bool TryParse(string json, out ServiceCommand? command)
    {
        command = null;
        if (string.IsNullOrWhiteSpace(json) || json.Length > 65_536) return false;
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) return false;
            var count = 0;
            var requestIdCount = 0;
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (property.Name == nameof(ServiceCommand.CommandType))
                {
                    count++;
                    if (property.Value.ValueKind != JsonValueKind.Number || !property.Value.TryGetInt32(out var value) ||
                        !Enum.IsDefined(typeof(ServiceCommandType), value)) return false;
                }
                else if (property.Name == nameof(ServiceCommand.RequestId))
                {
                    requestIdCount++;
                    if (requestIdCount != 1 || property.Value.ValueKind != JsonValueKind.String ||
                        !property.Value.TryGetGuid(out var requestId) || requestId == Guid.Empty) return false;
                }
            }
            if (count != 1) return false;
            command = JsonSerializer.Deserialize<ServiceCommand>(json, new JsonSerializerOptions { MaxDepth = 16 });
            return command != null;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
