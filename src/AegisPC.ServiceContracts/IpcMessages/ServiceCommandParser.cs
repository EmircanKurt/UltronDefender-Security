using System.Text.Json;

namespace AegisPC.ServiceContracts.IpcMessages;

/// <summary>Validates the command envelope before enum defaults can become a privileged operation.</summary>
public static class ServiceCommandParser
{
    /// <summary>
    /// Accepts an explicit, defined numeric CommandType exactly once; malformed, missing, duplicate,
    /// oversized or unknown commands return false and are never dispatched.
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
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (property.Name != nameof(ServiceCommand.CommandType)) continue;
                count++;
                if (property.Value.ValueKind != JsonValueKind.Number || !property.Value.TryGetInt32(out var value) ||
                    !Enum.IsDefined(typeof(ServiceCommandType), value)) return false;
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
