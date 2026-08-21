namespace AegisPC.Core.Models;

public class NetworkConnection
{
    public string ProcessName { get; set; } = string.Empty;
    public int PID { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string State { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;
}
