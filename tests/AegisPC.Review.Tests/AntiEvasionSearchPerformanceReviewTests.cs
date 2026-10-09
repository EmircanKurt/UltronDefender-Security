using System;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using AegisPC.Security.AntiEvasion;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Review.Tests;

/// <summary>Measures the changed search helper on identical inert bytes; this is not whole-PC scan performance.</summary>
public sealed class AntiEvasionSearchPerformanceReviewTests(ITestOutputHelper output)
{
    private delegate bool SpanSearch(ReadOnlySpan<byte> bytes, string token);

    /// <summary>Five alternating before/after repetitions preserve the exact fixed-token results and report elapsed/CPU/RAM.</summary>
    [Fact]
    public void FiveRuns_ChangedSearchHelper_PreservesCoverageAndReportsResources()
    {
        var method = typeof(AntiEvasionDetector).GetMethod("SpanContainsPattern", BindingFlags.NonPublic | BindingFlags.Static)!;
        var current = method.CreateDelegate<SpanSearch>();
        byte[] bytes = new byte[512 * 1024]; new Random(5840).NextBytes(bytes);
        string[] tokens = ["AmsiScanBuffer", "EtwEventWrite", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "amsiInitFailed"];
        System.Text.Encoding.ASCII.GetBytes("EtwEventWrite").CopyTo(bytes, bytes.Length - 40);
        bool[] expected = tokens.Select(t => LegacySearch(bytes, t)).ToArray();
        using var process = Process.GetCurrentProcess();
        for (int run = 1; run <= 5; run++)
        foreach (bool optimized in run % 2 == 0 ? new[] { true, false } : new[] { false, true })
        {
            var cpu = process.TotalProcessorTime; var timer = Stopwatch.StartNew();
            for (int i = 0; i < tokens.Length; i++) Assert.Equal(expected[i], optimized ? current(bytes, tokens[i]) : LegacySearch(bytes, tokens[i]));
            timer.Stop(); process.Refresh();
            output.WriteLine($"run={run} optimized={optimized} bytes={bytes.Length} tokens={tokens.Length} ms={timer.Elapsed.TotalMilliseconds:F3} cpu_ms={(process.TotalProcessorTime-cpu).TotalMilliseconds:F3} working_set_bytes={process.WorkingSet64}");
        }
    }

    // Exact old ASCII/UTF-16 loops from the pre-change checkpoint, retained only for this inert comparison.
    private static bool LegacySearch(ReadOnlySpan<byte> source, string pattern)
    {
        for (int i = 0; i <= source.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
                if (char.ToUpperInvariant((char)source[i + j]) != char.ToUpperInvariant(pattern[j])) { match = false; break; }
            if (match) return true;
        }
        for (int i = 0; i <= source.Length - pattern.Length * 2; i += 2)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
                if (char.ToUpperInvariant((char)(source[i + j * 2] | source[i + j * 2 + 1] << 8)) != char.ToUpperInvariant(pattern[j])) { match = false; break; }
            if (match) return true;
        }
        return false;
    }
}
