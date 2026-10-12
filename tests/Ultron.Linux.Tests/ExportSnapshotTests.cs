using System.Text.Json;
using Ultron.PortableInspection;
using Xunit;

namespace Ultron.Linux.Tests;

/// <summary>Verifies asynchronous export remains tied to its captured scan while a new scan resets the GUI list.</summary>
public sealed class ExportSnapshotTests
{
    /// <summary>Verifies caller mutation of nested arrays cannot rewrite a captured export, including its hash-bound evidence.</summary>
    [Fact]
    public async Task NestedArraysCannotRewriteCapturedEvidence()
    {
        var member = new InspectionReport { Path = "archive/member", Sha256 = "inert-hash", ReviewIndicators = ["Original review"] };
        var report = new InspectionReport { Path = "archive", Formats = ["ZIP"], Limitations = ["Original limitation"], Members = [member] };
        var snapshot = InspectionExportSnapshot.Capture("archive", "CompletedWithReportedCoverage", [report]);
        report.Formats[0] = "Changed format";
        report.Limitations[0] = "Changed limitation";
        member.ReviewIndicators[0] = "Changed review";
        snapshot.Reports[0].Members[0] = new() { Path = "replacement" };
        using var output = new MemoryStream();
        await snapshot.WriteAsync(output);
        using var json = JsonDocument.Parse(output.ToArray());
        var exported = Assert.Single(json.RootElement.GetProperty("Reports").EnumerateArray());
        Assert.Equal("ZIP", exported.GetProperty("Formats")[0].GetString());
        Assert.Equal("Original limitation", exported.GetProperty("Limitations")[0].GetString());
        var exportedMember = exported.GetProperty("Members")[0];
        Assert.Equal("archive/member", exportedMember.GetProperty("Path").GetString());
        Assert.Equal("inert-hash", exportedMember.GetProperty("Sha256").GetString());
        Assert.Equal("Original review", exportedMember.GetProperty("ReviewIndicators")[0].GetString());
    }

    /// <summary>Uses a bounded delayed output stream to verify scope, outcome and report membership cannot change mid-export.</summary>
    [Fact]
    public async Task DelayedExportRetainsCapturedScan()
    {
        var liveReports = new List<InspectionReport> { new() { Path = "first-scope/file", Limitations = ["Explicit fixture coverage"] } };
        var snapshot = InspectionExportSnapshot.Capture("first-scope", "CancelledIncomplete", liveReports);
        using var output = new DelayedOutput();
        var writing = snapshot.WriteAsync(output);
        await output.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        liveReports.Clear();
        liveReports.Add(new() { Path = "second-scope/file" });
        output.Resume.TrySetResult();
        await writing.WaitAsync(TimeSpan.FromSeconds(5));
        using var json = JsonDocument.Parse(output.ToArray());
        Assert.Equal("first-scope", json.RootElement.GetProperty("SelectedScope").GetString());
        Assert.Equal("CancelledIncomplete", json.RootElement.GetProperty("Outcome").GetString());
        Assert.Equal("first-scope/file", Assert.Single(json.RootElement.GetProperty("Reports").EnumerateArray()).GetProperty("Path").GetString());
        Assert.False(json.RootElement.GetProperty("MalwareFreeClaim").GetBoolean());
    }

    private sealed class DelayedOutput : MemoryStream
    {
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Resume = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length > 64 * 1024) throw new InvalidDataException("Inert export fixture exceeded its bounded buffer.");
            Started.TrySetResult();
            await Resume.Task.WaitAsync(cancellationToken);
            await base.WriteAsync(buffer, cancellationToken);
        }
    }
}
