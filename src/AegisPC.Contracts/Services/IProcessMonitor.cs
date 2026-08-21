using System.Collections.Generic;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IProcessMonitor
{
    Task<List<ProcessInfo>> GetAllProcessesAsync();
    Task<ProcessInfo?> GetProcessByPidAsync(int pid);
    Task<List<ProcessTreeNode>> GetProcessTreeAsync();
    Task RefreshAsync();
}
