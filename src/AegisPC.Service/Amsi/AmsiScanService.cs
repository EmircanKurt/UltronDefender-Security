using System;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Amsi
{
    public class AmsiScanService : IAmsiScanService
    {
        private readonly AegisPC.Security.Scanning.AmsiScanService _innerService;

        public bool IsAmsiSupported => _innerService.IsAmsiSupported;

        public AmsiScanService(ILogger<AegisPC.Security.Scanning.AmsiScanService>? logger = null)
        {
            _innerService = new AegisPC.Security.Scanning.AmsiScanService(logger);
        }

        public Task<AmsiScanResult> ScanStringAsync(string content, string contentName = "DynamicScript")
        {
            return _innerService.ScanStringAsync(content, contentName);
        }

        public Task<AmsiScanResult> ScanBufferAsync(byte[] buffer, string contentName = "MemoryBuffer")
        {
            return _innerService.ScanBufferAsync(buffer, contentName);
        }

        public void Dispose()
        {
            _innerService.Dispose();
        }
    }
}
