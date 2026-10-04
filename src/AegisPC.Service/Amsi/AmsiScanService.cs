using System;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Amsi
{
    /// <summary>Exposes the shared native-versus-heuristic AMSI result contract to the Windows service without performing registration.</summary>
    public class AmsiScanService : IAmsiScanService, IAmsiObservationProvider
    {
        private readonly AegisPC.Security.Scanning.AmsiScanService _innerService;

        /// <summary>Reports initialized provider availability only; individual results carry their completed or partial coverage.</summary>
        public bool IsAmsiSupported => _innerService.IsAmsiSupported;

        /// <summary>Returns the last actually completed native-provider observation without treating local fallback as health.</summary>
        public DateTime? LastNativeScanUtc => _innerService.LastNativeScanUtc;
        /// <summary>Reports the most recent native attempt's successful completion, separately from initialized support.</summary>
        public bool LastNativeRequestCompleted => _innerService.LastNativeRequestCompleted;

        /// <summary>Uses the shared decision engine and owns an optional injected native adapter for inert service tests.</summary>
        public AmsiScanService(ILogger<AegisPC.Security.Scanning.AmsiScanService>? logger = null,
            AegisPC.Security.Scanning.IAmsiNativeProvider? nativeProvider = null)
        {
            _innerService = new AegisPC.Security.Scanning.AmsiScanService(logger, nativeProvider);
        }

        /// <summary>Returns native provider status and separate heuristic hints without executing the script.</summary>
        public Task<AmsiScanResult> ScanStringAsync(string content, string contentName = "DynamicScript")
        {
            return _innerService.ScanStringAsync(content, contentName);
        }

        /// <summary>Returns native provider status and bounded fallback metadata for the supplied bytes.</summary>
        public Task<AmsiScanResult> ScanBufferAsync(byte[] buffer, string contentName = "MemoryBuffer")
        {
            return _innerService.ScanBufferAsync(buffer, contentName);
        }

        /// <summary>Releases the shared engine and its provider without changing AMSI registration or system settings.</summary>
        public void Dispose()
        {
            _innerService.Dispose();
        }
    }
}
