using System;
using System.IO;
using System.Text;

namespace AegisPC.Service.RealTime;

/// <summary>
/// Appends optional ETW observations without truncating existing logs or allowing unbounded growth.
/// Callers serialize writes; a full or unavailable log must not stop event processing.
/// </summary>
internal sealed class BoundedEtwLogWriter : IDisposable
{
    internal const long MaxLogBytes = 8L * 1024 * 1024;
    private const int FlushEveryLines = 64;
    private static readonly UTF8Encoding LogEncoding = new(false);
    private static readonly int NewLineByteCount = LogEncoding.GetByteCount(Environment.NewLine);

    private readonly StreamWriter _writer;
    private readonly long _maxLogBytes;
    private long _reservedBytes;
    private int _unflushedLines;

    internal BoundedEtwLogWriter(string path) : this(path, MaxLogBytes) { }

    internal BoundedEtwLogWriter(string path, long maxLogBytes)
    {
        if (maxLogBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maxLogBytes));
        _maxLogBytes = maxLogBytes;
        var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
        try
        {
            _reservedBytes = stream.Length;
            if (_reservedBytes >= _maxLogBytes)
                throw new IOException("ETW observation log has reached its byte budget.");
            _writer = new StreamWriter(stream, LogEncoding);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    internal bool TryWrite(string entry)
    {
        if (entry.Contains('\r') || entry.Contains('\n'))
            entry = entry.Replace('\r', ' ').Replace('\n', ' ');
        long entryBytes = LogEncoding.GetByteCount(entry) + NewLineByteCount;
        if (entryBytes > _maxLogBytes - _reservedBytes) return false;

        _writer.WriteLine(entry);
        _reservedBytes += entryBytes;
        if (++_unflushedLines < FlushEveryLines) return true;
        _writer.Flush();
        _unflushedLines = 0;
        return true;
    }

    /// <summary>Flushes buffered observations and closes the log without deleting prior data.</summary>
    public void Dispose() => _writer.Dispose();
}
