using System;
using System.Text;
using System.Threading;

namespace AegisPC.Security.Scanning;

/// <summary>Matches fixed ASCII tokens in ASCII or UTF-16LE bytes without converting arbitrary binary data to Unicode.</summary>
internal sealed class ContentBytePattern
{
    private const int SearchBlockBytes = 16 * 1024;
    private readonly byte[] _lower;
    private readonly byte _firstUpper;

    internal ContentBytePattern(string text)
    {
        if (string.IsNullOrEmpty(text) || !System.Linq.Enumerable.All(text, c => c <= 127))
            throw new ArgumentException("Content tokens must be nonempty ASCII identifiers.", nameof(text));
        _lower = Encoding.ASCII.GetBytes(text.ToLowerInvariant());
        _firstUpper = _lower[0] is >= (byte)'a' and <= (byte)'z' ? (byte)(_lower[0] - 32) : _lower[0];
    }

    internal bool Contains(ReadOnlySpan<byte> source, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        int offset = 0;
        while (offset <= source.Length - _lower.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int length = Math.Min(SearchBlockBytes, source.Length - _lower.Length - offset + 1);
            int candidate = source.Slice(offset, length).IndexOfAny(_lower[0], _firstUpper);
            if (candidate < 0) { offset += length; continue; }
            offset += candidate;
            if (Matches(source[offset..], wide: false) || Matches(source[offset..], wide: true)) return true;
            offset++;
        }
        return false;
    }

    private bool Matches(ReadOnlySpan<byte> source, bool wide)
    {
        int stride = wide ? 2 : 1;
        if (source.Length < _lower.Length * stride) return false;
        for (int i = 0; i < _lower.Length; i++)
        {
            byte value = source[i * stride];
            if (wide && source[i * stride + 1] != 0) return false;
            if (value is >= (byte)'A' and <= (byte)'Z') value += 32;
            if (value != _lower[i]) return false;
        }
        return true;
    }
}
