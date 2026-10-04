using System;
using System.Diagnostics;
using System.IO;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace AegisPC.Infrastructure.Logging;

/// <summary>Creates bounded per-user diagnostic logging without publishing raw paths, commands or exception messages.</summary>
public static class SerilogConfiguration
{
    /// <summary>
    /// Creates a rotating diagnostic logger in the current user's local application data, or an isolated supplied directory.
    /// Inaccessible storage falls back to a sanitized trace sink; a logging failure must not prevent protection startup.
    /// </summary>
    public static Serilog.ILogger Configure(string? logDirectory = null)
    {
        var formatter = new SafeDiagnosticFormatter();
        try
        {
            string directory = Path.GetFullPath(logDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "UltronDefender", "Logs"));
            Directory.CreateDirectory(directory);
            // The file sink can suppress opening failures. Verify access and remove only this owned probe.
            string probePath = Path.Combine(directory, ".diagnostic-probe-" + Guid.NewGuid().ToString("N") + ".tmp");
            using (var probe = new FileStream(probePath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                1, FileOptions.DeleteOnClose)) probe.WriteByte(0);
            return new LoggerConfiguration()
                .MinimumLevel.Information()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .WriteTo.File(formatter, Path.Combine(directory, "aegis-diagnostics-.log"),
                    rollingInterval: RollingInterval.Day, fileSizeLimitBytes: 1024 * 1024,
                    rollOnFileSizeLimit: true, retainedFileCountLimit: 10, shared: true)
                .CreateLogger();
        }
        catch (Exception exception)
        {
            var fallback = new LoggerConfiguration().MinimumLevel.Information()
                .WriteTo.Sink(new SafeTraceSink(formatter)).CreateLogger();
            fallback.Warning(exception, "Diagnostic file logging is unavailable; sanitized trace logging is used.");
            return fallback;
        }
    }

    private sealed class SafeTraceSink(SafeDiagnosticFormatter formatter) : ILogEventSink
    {
        public void Emit(LogEvent logEvent)
        {
            using var output = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
            formatter.Format(logEvent, output);
            Trace.WriteLine(output.ToString());
        }
    }
}
