using System.Text;

namespace AegisPC.Security.Scanning;

/// <summary>Content-only bounded text semantics shared by loose and decompressed member rule evaluation.</summary>
internal static class ContentRuleSemantics
{
    internal static bool IsBoundedText(ReadOnlySpan<byte> content)
    {
        if (content.Length is 0 or > 1024 * 1024) return false;
        try
        {
            string text = DecodeText(content);
            return text.All(c => !char.IsControl(c) || c is '\r' or '\n' or '\t' or '\f' or '\uFEFF');
        }
        catch (DecoderFallbackException) { return false; }
    }

    internal static string DecodeText(ReadOnlySpan<byte> content) =>
        content.Length >= 2 && content[0] == 0xff && content[1] == 0xfe ? new UnicodeEncoding(false, true, true).GetString(content[2..]) :
        content.Length >= 2 && content[0] == 0xfe && content[1] == 0xff ? new UnicodeEncoding(true, true, true).GetString(content[2..]) :
        new UTF8Encoding(false, true).GetString(content);
}
