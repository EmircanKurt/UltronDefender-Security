using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Infrastructure.Elevation
{
    public class ElevationService : IElevationService
    {
        private readonly ILogger<ElevationService>? _logger;

        public ElevationService(ILogger<ElevationService>? logger = null)
        {
            _logger = logger;
        }

        public bool IsElevated
        {
            get
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        public async Task<bool> RequestElevatedActionAsync(string command, string args, CancellationToken cancellationToken = default)
        {
            try
            {
                var helperPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AegisPC.ElevatedHelper.exe");
                if (!File.Exists(helperPath))
                {
                    // Fallback search in tools/output folder
                    helperPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "tools", "AegisPC.ElevatedHelper", "bin", "Debug", "net8.0-windows", "AegisPC.ElevatedHelper.exe");
                }

                var psi = new ProcessStartInfo
                {
                    FileName = helperPath,
                    Arguments = $"{command} {args}",
                    Verb = IsElevated ? string.Empty : "runas",
                    UseShellExecute = true
                };

                using var process = Process.Start(psi);
                if (process == null) return false;

                await process.WaitForExitAsync(cancellationToken);
                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to execute elevated helper action: {Command}", command);
                return false;
            }
        }
    }
}
