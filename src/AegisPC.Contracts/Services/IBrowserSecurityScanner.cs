using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IBrowserSecurityScanner
{
    Task<List<BrowserProfile>> ScanAllBrowsersAsync(CancellationToken cancellationToken = default);
    Task<BrowserProfile?> ScanBrowserAsync(BrowserType browserType, CancellationToken cancellationToken = default);
}
