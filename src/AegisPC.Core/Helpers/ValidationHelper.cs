using System.Text.RegularExpressions;

namespace AegisPC.Core.Helpers;

public static class ValidationHelper
{
    public static bool IsValidSha256(string hash) => !string.IsNullOrWhiteSpace(hash) && Regex.IsMatch(hash, "^[a-fA-F0-9]{64}$");
    
    public static bool IsValidPath(string path) => !string.IsNullOrWhiteSpace(path) && path.IndexOfAny(System.IO.Path.GetInvalidPathChars()) == -1;
    
    public static string SanitizeForLog(string input) => string.IsNullOrWhiteSpace(input) ? string.Empty : input.Replace("\r", "").Replace("\n", " ");
}
