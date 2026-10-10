using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Serilog.Events;
using Serilog.Formatting;

namespace AegisPC.Infrastructure.Logging;

/// <summary>
/// Formats operational diagnostics using identifiers, numeric metadata and exception code/method summaries only.
/// Raw templates, exception messages, commands, paths and arbitrary string properties are deliberately omitted.
/// </summary>
public sealed class SafeDiagnosticFormatter : ITextFormatter
{
    /// <summary>Writes one bounded event without executing a message renderer or exposing source file names.</summary>
    public void Format(LogEvent logEvent, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        ArgumentNullException.ThrowIfNull(output);
        output.Write(logEvent.Timestamp.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        output.Write(" level="); output.Write(logEvent.Level);
        output.Write(" event=");
        output.Write(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(logEvent.MessageTemplate.Text)))[..16]);
        if (logEvent.Properties.TryGetValue("SourceContext", out var context) &&
            context is ScalarValue { Value: string source } && IsSafeIdentifier(source))
        { output.Write(" source="); output.Write(source); }
        foreach (var property in logEvent.Properties.OrderBy(pair => pair.Key, StringComparer.Ordinal).Take(32))
        {
            if (property.Key == "SourceContext" || !IsSafeIdentifier(property.Key) ||
                property.Value is not ScalarValue scalar) continue;
            string? safeValue = FormatSafeScalar(scalar.Value);
            if (safeValue == null) continue;
            output.Write(' '); output.Write(property.Key); output.Write('='); output.Write(safeValue);
        }
        if (logEvent.Exception != null) WriteException(logEvent.Exception, output, 0);
        output.WriteLine();
    }

    private static string? FormatSafeScalar(object? value) => value switch
    {
        Guid identifier => identifier.ToString("D"),
        bool flag => flag ? "true" : "false",
        byte or sbyte or short or ushort or int or uint or long or ulong or decimal =>
            Convert.ToString(value, CultureInfo.InvariantCulture),
        double number when double.IsFinite(number) => number.ToString("R", CultureInfo.InvariantCulture),
        float number when float.IsFinite(number) => number.ToString("R", CultureInfo.InvariantCulture),
        Enum named when IsSafeIdentifier(named.ToString()) => named.ToString(),
        _ => null
    };

    private static void WriteException(Exception exception, TextWriter output, int depth)
    {
        if (depth >= 4) return;
        output.Write(" exception["); output.Write(depth); output.Write("]=");
        output.Write(exception.GetType().FullName);
        output.Write(" hresult=0x"); output.Write(exception.HResult.ToString("X8", CultureInfo.InvariantCulture));
        if (exception is Win32Exception native)
        { output.Write(" native="); output.Write(native.NativeErrorCode.ToString(CultureInfo.InvariantCulture)); }
        foreach (var frame in (new StackTrace(exception, false).GetFrames() ?? []).Take(8))
        {
            var method = frame.GetMethod();
            string identifier = method?.DeclaringType?.FullName + "." + method?.Name;
            if (!IsSafeIdentifier(identifier)) continue;
            output.Write(" at="); output.Write(identifier);
        }
        if (exception is AggregateException aggregate)
        {
            foreach (var inner in aggregate.InnerExceptions.Take(3)) WriteException(inner, output, depth + 1);
        }
        else if (exception.InnerException != null) WriteException(exception.InnerException, output, depth + 1);
    }

    private static bool IsSafeIdentifier(string value) => value.Length is > 0 and <= 256 &&
        value.All(character => char.IsLetterOrDigit(character) || character is '.' or '_' or '+' or '`' or '<' or '>');
}
