using System.Diagnostics;
using AegisPC.Security.Detection.YaraEngine;
using Microsoft.Extensions.Logging;

namespace Ultron.Linux.App;

// No custom rule folder is exposed in this preview. Only the shared engine's three bounded defaults are loaded.
internal static class DefaultManagedRules
{
    internal static YaraEngine Create()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Default Linux preview rules require an actual Linux host.");
        string directory = Directory.CreateTempSubdirectory("ultron-linux-default-rules-").FullName;
        try
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var engine = new YaraEngine(directory, new RuleLogger());
            if (engine.LoadedRuleCount != 3) throw new IOException("The default-only managed rule snapshot could not be fully loaded.");
            return engine;
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private sealed class RuleLogger : ILogger<YaraEngine>
    {
        /// <summary>Uses no persistent logging scope for the short-lived default snapshot.</summary>
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        /// <summary>Reports actual rule initialization errors while omitting routine informational entries.</summary>
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;
        /// <summary>Records loading failures for diagnosis; the snapshot's rule-count gate still rejects missing defaults.</summary>
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel)) Trace.TraceError("Managed preview rules: {0}", formatter(state, exception));
        }
    }
}
