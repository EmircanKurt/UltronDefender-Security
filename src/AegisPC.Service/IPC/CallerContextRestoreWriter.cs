using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using AegisPC.Core.Models;

namespace AegisPC.Service.IPC;

/// <summary>Never writes a user's restore path with the service's SYSTEM credentials.</summary>
internal static class CallerContextRestoreWriter
{
    internal static Task WriteAsync(WindowsIdentity caller, QuarantineEntry entry, Stream verifiedPlaintext,
        string? destinationOverride, CancellationToken ct) => WindowsIdentity.RunImpersonatedAsync(caller.AccessToken, async () =>
    {
        string destination = Path.GetFullPath(destinationOverride ?? entry.OriginalPath);
        string parent = Path.GetDirectoryName(destination) ?? throw new IOException("Missing restore directory.");
        RejectReparseAncestors(parent);
        Directory.CreateDirectory(parent);
        RejectReparseAncestors(parent);
        string staging = Path.Combine(parent, ".ultron-restore-" + Guid.NewGuid().ToString("N") + ".tmp");
        bool published = false;
        try
        {
            await using (var output = new FileStream(staging, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 81920, useAsync: true))
            {
                await verifiedPlaintext.CopyToAsync(output, 81920, ct).ConfigureAwait(false);
                await output.FlushAsync(ct).ConfigureAwait(false);
                if (output.Length != entry.FileSize) throw new CryptographicException("Restore length mismatch.");
                output.Position = 0;
                string hash = Convert.ToHexString(await SHA256.HashDataAsync(output, ct).ConfigureAwait(false));
                if (!string.Equals(hash, entry.SHA256, StringComparison.OrdinalIgnoreCase)) throw new CryptographicException("Restore content mismatch.");
            }
            ct.ThrowIfCancellationRequested();
            RejectReparseAncestors(parent);
            File.Move(staging, destination, overwrite: false);
            published = true;
        }
        finally
        {
            // Publication has committed. Never touch a subsequently recreated sibling or turn
            // a successful restore into failure through an optional cleanup race.
            if (!published)
            {
                try { if (File.Exists(staging)) File.Delete(staging); }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                { System.Diagnostics.Debug.WriteLine("Uncommitted caller restore staging cleanup failed: " + exception.Message); }
            }
        }
    });

    private static void RejectReparseAncestors(string path)
    {
        for (var current = new DirectoryInfo(path); current != null; current = current.Parent)
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Restore through reparse ancestors is not permitted.");
    }
}
