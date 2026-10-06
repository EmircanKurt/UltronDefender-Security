using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Checks inert documentation and in-memory test signatures without creating an antivirus test file on disk.</summary>
public sealed class AntivirusTestReferenceRegressionTests
{
    private static byte[] Canonical() => Encoding.ASCII.GetBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    [Theory]
    [InlineData("This article discusses EICAR-STANDARD testing, not a virus.")]
    [InlineData("EICAR-STANDARD-ANTIVIRUS-TEST-FILE documentation")]
    public void TestNameInDocumentation_IsNotAnAbsoluteThreat(string content) =>
        Assert.False(MalwareSignatureDatabase.CheckBytesPattern(Encoding.ASCII.GetBytes(content)).IsMatched);

    [Fact]
    public void LegacySyntheticMarker_IsNotAProductionSignature()
    {
        byte[] marker = Convert.FromBase64String("Gx8dEwkFCQMUDhIfDhMZBRcbFg0bCB8FChsDFhUbHgUOHwkOBQkTHQVjY2tiaA==")
            .Select(b => (byte)(b ^ 0x5a)).ToArray();
        Assert.False(MalwareSignatureDatabase.CheckBytesPattern(marker).IsMatched);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(60)]
    public void CanonicalTest_StillDetectedInMemory(int padding)
    {
        byte[] bytes = Canonical().Concat(Enumerable.Repeat((byte)' ', padding)).ToArray();
        var match = MalwareSignatureDatabase.CheckBytesPattern(bytes);
        Assert.True(match.IsMatched);
        Assert.Equal("TestMalware", match.ThreatCategory);
    }

    [Fact]
    public void CanonicalTest_AllPermittedTrailingWhitespaceDetectedInMemory() =>
        Assert.True(MalwareSignatureDatabase.CheckBytesPattern(Canonical().Concat(new byte[] { 32, 9, 10, 13, 26 }).ToArray()).IsMatched);

    [Fact]
    public void CanonicalTest_InvalidVariantsAreNotCanonical()
    {
        Assert.False(MalwareSignatureDatabase.CheckBytesPattern(Canonical().Concat(Enumerable.Repeat((byte)' ', 61)).ToArray()).IsMatched);
        Assert.False(MalwareSignatureDatabase.CheckBytesPattern(new byte[] { 32 }.Concat(Canonical()).ToArray()).IsMatched);
        Assert.False(MalwareSignatureDatabase.CheckBytesPattern(Canonical().Concat(new byte[] { 0 }).ToArray()).IsMatched);
        Assert.False(MalwareSignatureDatabase.CheckBytesPattern(Canonical().Concat(new byte[] { 12 }).ToArray()).IsMatched);
    }

    [Fact]
    public void KnownCanonicalHash_StillDetected()
    {
        string hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Canonical()));
        Assert.Equal(68, Canonical().Length);
        Assert.Equal("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F", hash);
        Assert.True(MalwareSignatureDatabase.CheckHash(hash).IsMatched);
    }

    [Fact]
    public async Task CanonicalArchiveMember_StillDetectedWithoutWritingToDisk()
    {
        using var memory = new MemoryStream();
        using (var write = new ZipArchive(memory, ZipArchiveMode.Create, true))
        using (var stream = write.CreateEntry("test-content.bin").Open()) stream.Write(Canonical());
        memory.Position = 0;
        using var archive = new ZipArchive(memory, ZipArchiveMode.Read);
        var result = await Inspect(archive.Entries[0]);
        Assert.True(result.IsMatched);
        Assert.Equal("TestMalware", result.ThreatCategory);
    }

    [Fact]
    public async Task BenignDocumentation_FileAndArchiveMemberAreNotTestThreats()
    {
        string path = Path.Combine(Path.GetTempPath(), "Ultron_Reference_" + Guid.NewGuid().ToString("N") + ".txt");
        const string documentation = "This manual describes EICAR-STANDARD antivirus test files. No executable test content is here.";
        try
        {
            await File.WriteAllTextAsync(path, documentation);
            Assert.False((await MalwareSignatureDatabase.CheckFileContentPatternsAsync(path)).IsMatched);
            using var memory = new MemoryStream();
            using (var write = new ZipArchive(memory, ZipArchiveMode.Create, true))
            using (var writer = new StreamWriter(write.CreateEntry("manual.txt").Open())) writer.Write(documentation);
            memory.Position = 0;
            using var archive = new ZipArchive(memory, ZipArchiveMode.Read);
            Assert.False((await Inspect(archive.Entries[0])).IsMatched);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    private static async Task<MalwareSignatureMatch> Inspect(ZipArchiveEntry entry)
    {
        Type inspector = typeof(MalwareSignatureDatabase).Assembly.GetType("AegisPC.Security.Scanning.ArchiveEntryInspector")!;
        var task = (Task)inspector.GetMethod("InspectAsync", BindingFlags.Static | BindingFlags.NonPublic)!
            .Invoke(null, new object?[] { entry, CancellationToken.None, null })!;
        await task;
        object tuple = task.GetType().GetProperty("Result")!.GetValue(task)!;
        return (MalwareSignatureMatch)tuple.GetType().GetField("Item2")!.GetValue(tuple)!;
    }
}
