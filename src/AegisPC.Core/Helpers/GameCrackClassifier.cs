namespace AegisPC.Core.Helpers;

/// <summary>Legacy compatibility surface. No documented/versioned hash catalog exists, so no trust exception is granted.</summary>
public static class GameCrackClassifier
{
    /// <summary>Names, directories and unverified hashes cannot establish trust or suppress independent evidence.</summary>
    public static bool IsGameCrackOrEmulator(string filePath) => false;
}
