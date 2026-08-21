using System;
using System.IO;
using Serilog;
using Serilog.Events;

namespace AegisPC.Infrastructure.Logging
{
    /// <summary>
    /// Configures Serilog logging for the application.
    /// </summary>
    public static class SerilogConfiguration
    {
        /// <summary>
        /// Configures and returns the Serilog logger instance.
        /// </summary>
        public static Serilog.ILogger Configure()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var logDir = Path.Combine(appData, "AegisPC", "Logs");
            Directory.CreateDirectory(logDir);
            var logPath = Path.Combine(logDir, "aegis-.log");

            var loggerConfig = new LoggerConfiguration()
#if DEBUG
                .MinimumLevel.Debug()
#else
                .MinimumLevel.Information()
#endif
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .Enrich.FromLogContext()
                .Enrich.WithProperty("MachineName", Environment.MachineName)
                .Enrich.WithProperty("ProcessId", Environment.ProcessId)
                // Simplistic filtering of sensitive data
                .Filter.ByExcluding(logEvent =>
                    logEvent.MessageTemplate.Text.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                    logEvent.MessageTemplate.Text.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                    logEvent.MessageTemplate.Text.Contains("cookie", StringComparison.OrdinalIgnoreCase))
                .WriteTo.File(
                    path: logPath,
                    rollingInterval: RollingInterval.Day,
                    fileSizeLimitBytes: 10 * 1024 * 1024, // 10MB
                    retainedFileCountLimit: 30,
                    outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} {Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}"
                );

            return loggerConfig.CreateLogger();
        }
    }
}
