using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Tests;

/// <summary>Short, inert synthetic regression selection; no installed product storage, live observer or actions.</summary>
public sealed class ReviewStageOneSafetyTests(ITestOutputHelper output)
{
    [Fact]
    public void ExplicitNewTemporaryRoot_IsRequired()
    {
        Assert.Throws<ArgumentNullException>(() => new ReviewStageOneFixture(null!));
        Assert.Throws<ArgumentException>(() => new ReviewStageOneFixture(Path.GetTempPath()));
        Assert.Throws<ArgumentException>(() => new ReviewStageOneFixture(AppContext.BaseDirectory));
        using var fixture = ReviewStageOneFixture.Create();
        Assert.Throws<ArgumentException>(() => new ReviewStageOneFixture(fixture.Root));
        Assert.All(new[] { fixture.InputDirectory, fixture.RulesDirectory, fixture.SettingsPath, fixture.DatabasePath,
            fixture.ReportsPath, fixture.CacheDirectory, fixture.VaultDirectory },
            path => Assert.StartsWith(fixture.Root + Path.DirectorySeparatorChar, path, StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("../outside.bin")]
    [InlineData("../../outside.bin")]
    [InlineData("input/note.txt:stream")]
    [InlineData("input/ambiguous. /note.txt")]
    [InlineData("input/NUL.txt")]
    public void FixturePathEscapeOrAmbiguousRoute_IsRejected(string relative)
    {
        using var fixture = ReviewStageOneFixture.Create();
        Assert.Throws<InvalidOperationException>(() => fixture.EnsureContainedPath(Path.Combine(fixture.Root, relative)));
    }

    [Fact]
    public async Task FactoryAdapters_RejectOutsideRootAndLiveProcessContext()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string sibling = fixture.Root + "_sibling" + Path.DirectorySeparatorChar + "never-read.txt";
        Assert.Throws<InvalidOperationException>(() => fixture.ImportReadOnlyInput(@"\\ultron-review-invalid\share\never-read.bin", "copy.bin"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.HashService.ComputeSha256Async(sibling));
        var hub = fixture.CreateHub();
        Assert.DoesNotContain(hub.RegisteredDetectors, plugin => plugin.DetectorId.Contains("Amsi", StringComparison.OrdinalIgnoreCase));
        await Assert.ThrowsAsync<InvalidOperationException>(() => hub.EvaluateAsync(new DetectionContext { FilePath = sibling }));
        string harmless = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("An ordinary synthetic local note."));
        await Assert.ThrowsAsync<InvalidOperationException>(() => hub.EvaluateAsync(new DetectionContext { FilePath = harmless, ProcessId = 1 }));
        Assert.All(Directory.GetFiles(fixture.RulesDirectory, "*.yar"), path =>
            Assert.Contains("condition: false", File.ReadAllText(path)));
    }

    /// <summary>
    /// Measures the same bounded synthetic inputs with one or two workers. Timing is descriptive, not a
    /// speed guarantee: input bytes are logical, CPU/memory cover this host process and physical I/O is unknown.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task SyntheticSharedPipeline_ReportsCoverageAndLeavesInputsUnchanged(int workerCount)
    {
        using var fixture = ReviewStageOneFixture.Create();
        byte[] wide = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("An ordinary synthetic UTF-16 note.")).ToArray();
        string[] paths =
        [
            fixture.WriteInput("small.txt", Encoding.UTF8.GetBytes("An ordinary synthetic UTF-8 note.")),
            fixture.WriteInput("wide.txt", wide),
            fixture.WriteInput("larger.txt", Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("ordinary local synthetic data\n", 1600)))),
            fixture.WriteInput("opaque.bin", Enumerable.Repeat((byte)0xff, 4096).ToArray())
        ];
        var expectedHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string path in paths) expectedHashes[path] = await fixture.ComputeInputIdentityAsync(path);
        var hub = fixture.CreateHub();
        var classifier = new FileContentClassifier();
        var results = new ConcurrentDictionary<string, DetectionResult>(StringComparer.OrdinalIgnoreCase);
        var input = Channel.CreateBounded<(string Path, long QueuedAt)>(new BoundedChannelOptions(2)
        { FullMode = BoundedChannelFullMode.Wait, SingleWriter = true, SingleReader = workerCount == 1 });
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var measurements = new ScanMeasurementRecorder();
        using var stages = measurements.BeginPipelineStages();

        Task[] workers = Enumerable.Range(0, workerCount).Select(async _ =>
        {
            await foreach (var item in input.Reader.ReadAllAsync(budget.Token))
            {
                using var attempt = measurements.Begin(item.Path, item.QueuedAt);
                await using var lockedSource = new FileStream(fixture.EnsureContainedPath(item.Path), FileMode.Open, FileAccess.Read, FileShare.Read);
                string hash = await fixture.HashService.ComputeSha256Async(item.Path, budget.Token);
                Assert.Equal(expectedHashes[item.Path], hash, ignoreCase: true);
                FileContentClassification classification = await classifier.ClassifyAsync(lockedSource, Path.GetExtension(item.Path), budget.Token);
                var context = new DetectionContext
                {
                    FilePath = item.Path, FileSize = lockedSource.Length, SHA256 = hash,
                    ContentClassification = classification,
                    CoverageLimitations = [.. classification.CoverageLimitations],
                    SharedScan = new ScanContext(item.Path, hash, lockedSource.Length)
                    { LockedContent = lockedSource, ContentClassification = classification }
                };
                DetectionResult result = await hub.EvaluateAsync(context, budget.Token);
                Assert.Equal(expectedHashes[item.Path], result.SHA256, ignoreCase: true);
                Assert.NotEqual(DetectionVerdict.ConfirmedMalicious, result.Verdict);
                Assert.True(results.TryAdd(item.Path, result));
                attempt.Complete(FileScanOutcome.Success, inspectionComplete: result.IsComplete, fromCache: false);
            }
        }).ToArray();
        async Task ProduceAsync()
        {
            Exception? producerFailure = null;
            try
            {
                foreach (string path in paths)
                    await input.Writer.WriteAsync((path, Stopwatch.GetTimestamp()), budget.Token);
            }
            catch (Exception error) { producerFailure = error; throw; }
            finally { input.Writer.TryComplete(producerFailure); }
        }
        // Even a producer/worker failure joins all owned tasks before fixture disposal.
        await Task.WhenAll(workers.Append(ProduceAsync()));

        var summary = measurements.Snapshot();
        var volume = Assert.Single(summary.Volumes);
        Assert.Equal(paths.Length, volume.Attempts);
        Assert.Equal(paths.Length, volume.SuccessfulAttempts);
        Assert.Equal(paths.Length, volume.FinishedAttempts);
        Assert.Equal(3, volume.CompleteCoverageAttempts);
        Assert.Equal(1, volume.PartialCoverageAttempts);
        Assert.Equal(0, volume.UnknownCoverageAttempts);
        Assert.Equal(0, volume.InterruptedAttempts);
        Assert.Equal(0, volume.CachedAttempts);
        Assert.InRange(volume.PeakActiveWorkers, 1, workerCount);
        Assert.Equal(paths.Sum(path => new FileInfo(path).Length), volume.LogicalInputBytes);
        Assert.True(volume.FilesPerSecond > 0);
        Assert.True(volume.LogicalInputMiBPerSecond > 0);
        Assert.True(summary.HashStageMs >= 0);
        Assert.True(summary.ContentStageMs >= 0);
        Assert.True(summary.DetectorStageMs >= 0);
        Assert.Null(summary.DiscoveryStageMs);
        Assert.Null(summary.StabilityStageMs);
        Assert.Null(summary.PhysicalInputMiBPerSecond);
        Assert.Null(volume.OutputQueueP95UpperBoundMs);
        Assert.All(paths.Take(3), path => Assert.Equal(DetectionVerdict.Clean, results[path].Verdict));
        Assert.Equal(DetectionVerdict.Unknown, results[paths[^1]].Verdict);
        Assert.False(results[paths[^1]].IsComplete);
        foreach (string path in paths) Assert.Equal(expectedHashes[path], await fixture.ComputeInputIdentityAsync(path));
        output.WriteLine("Synthetic fixture only; stages may overlap; process CPU/memory include the test host. Physical I/O, stability and output queue: unknown.");
        output.WriteLine($"workers={workerCount} " + JsonSerializer.Serialize(summary));
    }
}
