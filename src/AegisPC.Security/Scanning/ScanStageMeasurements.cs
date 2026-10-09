using System.Diagnostics;

namespace AegisPC.Security.Scanning;

/// <summary>Only concrete, instrumented operations contribute; missing stage measurements stay unknown.</summary>
internal enum ScanStageTiming { Discovery, Stability, Hash, Content, Detector }

/// <summary>Flows the owned measurement sink through asynchronous work without recording paths or file content.</summary>
internal static class ScanStageMeasurements
{
    private sealed class Context(Action<ScanStageTiming, double> sink, Context? previous)
    {
        internal readonly Action<ScanStageTiming, double> Sink = sink;
        internal readonly Context? Previous = previous;
        internal int Closed;
    }
    private sealed class ActiveStage(Context context, ScanStageTiming stage, ActiveStage? previous)
    {
        internal readonly Context Context = context;
        internal readonly ScanStageTiming Stage = stage;
        internal readonly ActiveStage? Previous = previous;
        internal int Closed;
    }
    private static readonly AsyncLocal<Context?> Current = new();
    private static readonly AsyncLocal<ActiveStage?> Active = new();

    internal static IDisposable Activate(Action<ScanStageTiming, double> sink)
    {
        var context = new Context(sink, Current.Value);
        Current.Value = context;
        return new Once(() =>
        {
            Interlocked.Exchange(ref context.Closed, 1);
            if (ReferenceEquals(Current.Value, context)) Current.Value = Available(context.Previous);
        });
    }

    /// <summary>Measures elapsed wall time, including cancellation; nested measurements of the same stage/sink are counted once.</summary>
    internal static IDisposable Measure(ScanStageTiming stage)
    {
        var context = Available(Current.Value);
        if (context == null) return Empty.Instance;
        for (var parent = Active.Value; parent != null; parent = parent.Previous)
            if (Volatile.Read(ref parent.Closed) == 0 && Volatile.Read(ref parent.Context.Closed) == 0 &&
                parent.Stage == stage && ReferenceEquals(parent.Context.Sink, context.Sink)) return Empty.Instance;

        var active = new ActiveStage(context, stage, AvailableStage(Active.Value));
        Active.Value = active;
        long started = Stopwatch.GetTimestamp();
        return new Once(() =>
        {
            Interlocked.Exchange(ref active.Closed, 1);
            if (Volatile.Read(ref context.Closed) == 0)
                context.Sink(stage, Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            if (ReferenceEquals(Active.Value, active)) Active.Value = AvailableStage(active.Previous);
        });
    }

    private static Context? Available(Context? context)
    {
        while (context != null && Volatile.Read(ref context.Closed) != 0) context = context.Previous;
        return context;
    }

    private static ActiveStage? AvailableStage(ActiveStage? stage)
    {
        while (stage != null && (Volatile.Read(ref stage.Closed) != 0 || Volatile.Read(ref stage.Context.Closed) != 0)) stage = stage.Previous;
        return stage;
    }

    private sealed class Once(Action end) : IDisposable
    {
        private Action? _end = end;
        public void Dispose() => Interlocked.Exchange(ref _end, null)?.Invoke();
    }
    private sealed class Empty : IDisposable
    {
        internal static readonly Empty Instance = new();
        public void Dispose() { }
    }
}
