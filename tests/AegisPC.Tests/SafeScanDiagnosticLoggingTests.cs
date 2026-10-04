using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Logging;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert logging/coordinator fixtures; no host scan, service, quarantine or process action is invoked.</summary>
public sealed class SafeScanDiagnosticLoggingTests
{
    /// <summary>An old Failed row with missing diagnostics never presents zero per-file errors as engine success or invents its start date.</summary>
    [Fact]
    public void LegacyFailedReport_SeparatesUnknownEngineFailureFromPerFileCounters()
    {
        var report = new AegisPC.App.Services.ScanReportRecord
        {
            Result = new ScanResult { Status = ScanStatus.Failed, ScannedFiles = 53151, FailedFiles = 0,
                CompletedAt = DateTime.UtcNow }
        };
        Assert.Equal("Başlangıç zamanı kaydedilmedi", report.DateText);
        Assert.Contains("Başarısız", report.Summary);
        Assert.Contains("0 dosya hatası", report.Summary);
        Assert.Contains("Motor hatası ayrıntısı kaydedilmemiş", report.Summary);
        Assert.Null(report.Result.FailureInfo);
        Assert.Equal(default, report.Result.StartedAt);
    }

    /// <summary>Private text is omitted while a correlation ID and actual native failure code remain diagnosable.</summary>
    [Fact]
    public void Formatter_OmitsPrivateTextButKeepsNativeFailureAndCorrelation()
    {
        var parser = new Serilog.Parsing.MessageTemplateParser();
        var correlation = Guid.NewGuid();
        var exception = new Win32Exception(5, @"private-command C:\Users\fixture\private-file");
        var logEvent = new LogEvent(DateTimeOffset.UtcNow, LogEventLevel.Error, exception,
            parser.Parse(@"Interpolated secret C:\Users\fixture\private-file private-command"),
            [new LogEventProperty("SourceContext", new ScalarValue("AegisPC.Security.Scanning.ScanCoordinatorService")),
             new LogEventProperty("ScanId", new ScalarValue(correlation)),
             new LogEventProperty("ObjectPath", new ScalarValue(@"C:\Users\fixture\private-file")),
             new LogEventProperty("CommandLine", new ScalarValue("private-command")),
             new LogEventProperty("TotalFiles", new ScalarValue(53151))]);
        using var output = new StringWriter();
        new SafeDiagnosticFormatter().Format(logEvent, output);
        string rendered = output.ToString();
        Assert.Contains(correlation.ToString("D"), rendered);
        Assert.Contains("TotalFiles=53151", rendered);
        Assert.Contains("System.ComponentModel.Win32Exception", rendered);
        Assert.Contains("native=5", rendered);
        Assert.Contains("hresult=0x", rendered);
        Assert.DoesNotContain("private", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ObjectPath", rendered);
        Assert.DoesNotContain("CommandLine", rendered);
        Assert.DoesNotContain(@"C:\", rendered);
    }

    /// <summary>The real coordinator sends a synthetic failure through the file provider without losing its result identity.</summary>
    [Fact]
    public async Task CoordinatorFailure_ReachesBoundedFileLoggerWithSafeDetails()
    {
        string folder = Path.Combine(Path.GetTempPath(), "UltronDiagnosticFixture-" + Guid.NewGuid().ToString("N"));
        try
        {
            var diagnostic = SerilogConfiguration.Configure(folder);
            ScanResult result;
            using (var logger = (IDisposable)diagnostic)
            using (var factory = LoggerFactory.Create(builder => builder.AddSerilog(diagnostic, dispose: false)))
            {
                var coordinator = new ScanCoordinatorService(new ThrowingScanner(), new SecurityFindingService(),
                    logger: factory.CreateLogger<ScanCoordinatorService>());
                result = Assert.IsType<ScanResult>(await coordinator.StartScanAsync(ScanType.Custom, "inert fixture"));
                Assert.Equal(ScanStatus.Failed, result.Status);
                Assert.NotNull(result.FailureInfo);
                Assert.NotEqual(default, result.StartedAt);
                Assert.Equal(5, result.FailureInfo!.NativeErrorCode);
            }
            string contents = string.Join("\n", Directory.GetFiles(folder, "*.log").Select(File.ReadAllText));
            Assert.Contains(result.FailureInfo.CorrelationId.ToString("D"), contents);
            Assert.Contains("ScanCoordinatorService", contents);
            Assert.Contains("Win32Exception", contents);
            Assert.Contains("native=5", contents);
            Assert.DoesNotContain("private-command", contents);
            Assert.DoesNotContain(@"C:\Users\", contents);
        }
        finally
        {
            if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
        }
    }

    /// <summary>Unavailable logging storage cannot crash initialization or overwrite the object blocking its directory.</summary>
    [Fact]
    public void UnavailableDiagnosticDirectory_DoesNotThrowOrOverwriteBlocker()
    {
        string folder = Path.Combine(Path.GetTempPath(), "UltronDiagnosticBlocked-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string blocker = Path.Combine(folder, "blocked");
        try
        {
            File.WriteAllText(blocker, "inert owned fixture");
            var diagnostic = SerilogConfiguration.Configure(blocker);
            using var logger = (IDisposable)diagnostic;
            diagnostic.Error(new IOException("private-command"), "Synthetic blocked log fixture");
            Assert.Equal("inert owned fixture", File.ReadAllText(blocker));
            Assert.Empty(Directory.GetFiles(folder, "*.log"));
        }
        finally { File.Delete(blocker); Directory.Delete(folder); }
    }

    private sealed class ThrowingScanner : IFileScanner
    {
        public bool IsPaused => false;
        public void PauseScan() { }
        public void ResumeScan() { }
        public Task<SecurityFinding?> ScanFileAsync(string path, CancellationToken cancellationToken = default) =>
            Task.FromResult<SecurityFinding?>(null);
        public Task<FileScanDetailedResult> ScanFileDetailedAsync(string path, TimeSpan perFileTimeout,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero));
        public Task<ScanResult> ScanDirectoryAsync(string path, ScanType scanType,
            IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default) =>
            Task.FromException<ScanResult>(new Win32Exception(5, @"private-command C:\Users\fixture\private-file"));
    }
}
