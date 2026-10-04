using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Service.RealTime;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Benign ETW lifecycle and source-policy regressions; no system trace session is started.</summary>
public sealed class EtwObservationSafetyTests
{
    /// <summary>Ensures a completed ETW pump cannot be advertised as active without touching OS tracing.</summary>
    [Theory]
    [InlineData(typeof(EtwProcessMonitor))]
    [InlineData(typeof(EtwImageLoadMonitor))]
    public void CompletedMessagePump_IsNotReportedAsRunning(Type monitorType)
    {
        using var monitor = monitorType == typeof(EtwProcessMonitor)
            ? (IDisposable)new EtwProcessMonitor()
            : new EtwImageLoadMonitor();
        var runningField = monitorType.GetField("_isRunning", BindingFlags.Instance | BindingFlags.NonPublic);
        var taskField = monitorType.GetField("_processingTask", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(runningField);
        Assert.NotNull(taskField);
        runningField.SetValue(monitor, true);
        taskField.SetValue(monitor, Task.CompletedTask);

        bool isRunning = (bool)monitorType.GetProperty("IsRunning")!.GetValue(monitor)!;
        Assert.False(isRunning);
    }

    /// <summary>Guards live-session wiring and prevents path heuristics from creating direct threat findings.</summary>
    [Fact]
    public void EtwSessions_AreLiveAndPathHeuristicsDoNotCreateThreatFindings()
    {
        string processSource = ReadSource("EtwProcessMonitor.cs");
        string imageSource = ReadSource("EtwImageLoadMonitor.cs");

        Assert.DoesNotContain("CircularBufferMB", processSource, StringComparison.Ordinal);
        Assert.DoesNotContain("CircularBufferMB", imageSource, StringComparison.Ordinal);
        Assert.DoesNotContain("AddFindingAsync", processSource, StringComparison.Ordinal);
        Assert.DoesNotContain("AddFindingAsync", imageSource, StringComparison.Ordinal);
        Assert.DoesNotContain("BehaviorEventType.ProcessInjection", imageSource, StringComparison.Ordinal);
        Assert.Contains("session.Source.Process()", processSource, StringComparison.Ordinal);
        Assert.Contains("session.Source.Process()", imageSource, StringComparison.Ordinal);
        Assert.Contains("data.PayloadByName(\"ProcessID\")", processSource, StringComparison.Ordinal);
        Assert.Contains("data.PayloadByName(\"ProcessID\")", imageSource, StringComparison.Ordinal);
        Assert.DoesNotContain("Cmd: {commandLine}", processSource, StringComparison.Ordinal);
        Assert.Contains("BoundedEtwLogWriter", processSource, StringComparison.Ordinal);
        Assert.Contains("BoundedEtwLogWriter", imageSource, StringComparison.Ordinal);
    }

    /// <summary>Uses an isolated benign file to verify append-only behavior and the configured byte budget.</summary>
    [Fact]
    public void BoundedObservationLog_AppendsWithoutTruncatingAndStopsAtBudget()
    {
        string directory = Path.Combine(Path.GetTempPath(), "UltronEtwReview-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "observation.log");
        try
        {
            File.WriteAllText(path, "seed", new UTF8Encoding(false));
            long exactBudget = new FileInfo(path).Length + Encoding.UTF8.GetByteCount("ok" + Environment.NewLine);
            var writerType = typeof(EtwProcessMonitor).Assembly.GetType("AegisPC.Service.RealTime.BoundedEtwLogWriter");
            Assert.NotNull(writerType);
            var constructor = writerType.GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null, types: new[] { typeof(string), typeof(long) }, modifiers: null);
            var tryWrite = writerType.GetMethod("TryWrite", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(constructor);
            Assert.NotNull(tryWrite);

            using (var writer = (IDisposable)constructor.Invoke(new object[] { path, exactBudget }))
            {
                Assert.True((bool)tryWrite.Invoke(writer, new object[] { "ok" })!);
                Assert.False((bool)tryWrite.Invoke(writer, new object[] { "overflow" })!);
            }

            Assert.Equal(exactBudget, new FileInfo(path).Length);
            Assert.Equal("seedok" + Environment.NewLine, File.ReadAllText(path));
        }
        finally
        {
            File.Delete(path);
            Directory.Delete(directory);
        }
    }

    private static string ReadSource(string fileName)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "AegisPC.sln")))
            directory = directory.Parent;

        string root = directory?.FullName ?? throw new DirectoryNotFoundException("Test checkout could not be located.");
        return File.ReadAllText(Path.Combine(root, "src", "AegisPC.Service", "RealTime", fileName));
    }
}
