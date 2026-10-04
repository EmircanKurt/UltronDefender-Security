using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Data.Sqlite;

namespace AegisPC.Security.Safety;

/// <summary>Backs up legacy data before replacing permissive ACLs; failure leaves vault construction closed.</summary>
internal static class VaultSecurityPolicy
{
    private const string MarkerName = "vault.acl-v1.marker";
    private const string PendingName = "vault.acl-v1.pending";

    internal static bool Prepare(string vault, bool customVault)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Vault ACL enforcement requires Windows.");
        RejectReparseAncestors(vault);
        if (!customVault) VerifyProductionAncestors(vault);
        string marker = Path.Combine(vault, MarkerName);
        bool initialized = File.Exists(marker) && HasStrictAcl(vault, customVault);
        bool hasLegacy = Directory.EnumerateFiles(vault).Any(file => !IsLockFile(file) && !Path.GetFileName(file).Equals(MarkerName, StringComparison.OrdinalIgnoreCase));
        string? backup = null;
        if (!initialized && hasLegacy) backup = CreateVerifiedBackup(vault, customVault);
        var directory = new DirectoryInfo(vault);
        directory.SetAccessControl(DirectoryAcl(customVault));
        foreach (string file in Directory.EnumerateFiles(vault))
        {
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new IOException("Vault state cannot contain a reparse file.");
            if (IsLockFile(file)) continue; // Held locks install and verify their ACL through their native handle.
            new FileInfo(file).SetAccessControl(FileAcl(customVault));
        }
        foreach (string child in Directory.EnumerateDirectories(vault))
        {
            // Unexpected nested state has no known safe migration format; do not leave an accessible payload subtree.
            throw new IOException("Unexpected vault subdirectory requires an explicit offline migration: " + Path.GetFileName(child));
        }
        if (!initialized)
        {
            // An untrusted marker cannot become a valid migration proof merely because its ACL was hardened.
            if (File.Exists(marker)) File.Delete(marker);
            using var stream = new FileStream(Path.Combine(vault, PendingName), FileMode.Create, FileAccess.Write, FileShare.None);
            stream.Write(Encoding.UTF8.GetBytes(backup ?? "fresh-vault"));
            stream.Flush(true);
        }
        return initialized;
    }

    internal static void Complete(string vault, bool alreadyTrusted)
    {
        if (alreadyTrusted) return;
        // Only publish the ownership/ACL proof after the database ownership transition also completed.
        File.Move(Path.Combine(vault, PendingName), Path.Combine(vault, MarkerName), overwrite: false);
    }

    private static string CreateVerifiedBackup(string vault, bool customVault)
    {
        string parent = customVault
            ? Path.GetDirectoryName(Path.GetFullPath(vault)) ?? throw new IOException("Vault backup parent is unavailable.")
            : PrepareProductionBackupRoot();
        string backup = Path.Combine(parent, Path.GetFileName(vault) + ".acl-v1." + Guid.NewGuid().ToString("N") + ".backup");
        new DirectoryInfo(backup).Create(DirectoryAcl(customVault));
        string database = Path.Combine(vault, "QuarantineVault.db");
        if (File.Exists(database))
        {
            using var original = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
            using var snapshot = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path.Combine(backup, "QuarantineVault.db"), Pooling = false }.ToString());
            original.Open(); snapshot.Open(); original.BackupDatabase(snapshot);
            using var integrity = snapshot.CreateCommand();
            integrity.CommandText = "PRAGMA integrity_check;";
            if (!string.Equals(integrity.ExecuteScalar()?.ToString(), "ok", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Vault ACL transition backup failed SQLite verification.");
        }
        foreach (string file in Directory.EnumerateFiles(vault))
        {
            string name = Path.GetFileName(file);
            if (IsLockFile(file) || name.Equals("QuarantineVault.db", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("QuarantineVault.db-wal", StringComparison.OrdinalIgnoreCase) || name.Equals("QuarantineVault.db-shm", StringComparison.OrdinalIgnoreCase)) continue;
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new IOException("Legacy vault backup refuses reparse files.");
            string target = Path.Combine(backup, name);
            using var input = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var output = new FileStream(target, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            input.CopyTo(output);
            output.Flush(true);
            input.Position = 0; output.Position = 0;
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(input), SHA256.HashData(output)))
                throw new InvalidDataException("Vault ACL transition backup content verification failed.");
        }
        return backup;
    }

    private static DirectorySecurity DirectoryAcl(bool custom)
    {
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(Owner(custom));
        foreach (var sid in AllowedSids(custom))
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return acl;
    }

    private static bool HasStrictAcl(string vault, bool custom)
    {
        var acl = new DirectoryInfo(vault).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!acl.AreAccessRulesProtected || owner == null || !owner.Equals(Owner(custom))) return false;
        var allowed = AllowedSids(custom).Select(s => s.Value).ToHashSet(StringComparer.Ordinal);
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        return rules.Length > 0 && rules.All(r => r.AccessControlType == AccessControlType.Allow &&
            allowed.Contains(r.IdentityReference.Value) && r.FileSystemRights == FileSystemRights.FullControl);
    }

    private static FileSecurity FileAcl(bool custom)
    {
        var acl = new FileSecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(Owner(custom));
        foreach (var sid in AllowedSids(custom))
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        return acl;
    }

    internal static FileSecurity CreateLockAcl(bool customVault) => FileAcl(customVault);

    internal static bool IsStrictFileAcl(FileSecurity acl, bool customVault)
    {
        var owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!acl.AreAccessRulesProtected || owner == null || !owner.Equals(Owner(customVault))) return false;
        var allowed = AllowedSids(customVault).Select(s => s.Value).ToHashSet(StringComparer.Ordinal);
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        return rules.All(r => r.AccessControlType == AccessControlType.Allow &&
            allowed.Contains(r.IdentityReference.Value) && r.FileSystemRights == FileSystemRights.FullControl) &&
            allowed.SetEquals(rules.Select(r => r.IdentityReference.Value));
    }

    private static SecurityIdentifier Owner(bool custom) => custom
        ? WindowsIdentity.GetCurrent().User ?? throw new IOException("Current vault identity has no SID.")
        : new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

    private static SecurityIdentifier[] AllowedSids(bool custom)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        return custom ? new[] { system, admins, Owner(true) } : new[] { system, admins };
    }

    private static bool IsLockFile(string file) => Path.GetFileName(file).Equals("vault.operations.lock", StringComparison.OrdinalIgnoreCase) ||
        Path.GetFileName(file).Equals("vault.init.lock", StringComparison.OrdinalIgnoreCase);

    private static void RejectReparseAncestors(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path)); current != null; current = current.Parent)
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Vault ancestry cannot include a reparse directory.");
    }

    private static string PrepareProductionBackupRoot()
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "UltronDefenderRecoveryBackups");
        RejectReparseAncestors(Path.GetDirectoryName(root)!);
        if (Directory.Exists(root))
        {
            if (!HasStrictAcl(root, false)) throw new IOException("Recovery backup root is not service-owned; an offline migration is required.");
        }
        else new DirectoryInfo(root).Create(DirectoryAcl(false));
        RejectReparseAncestors(root);
        return root;
    }

    private static void VerifyProductionAncestors(string vault)
    {
        var trustedInstaller = (SecurityIdentifier)new NTAccount("NT SERVICE", "TrustedInstaller").Translate(typeof(SecurityIdentifier));
        var allowed = AllowedSids(false).Select(s => s.Value).ToHashSet(StringComparer.Ordinal);
        allowed.Add(trustedInstaller.Value);
        const FileSystemRights dangerous = FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.Delete |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        for (var parent = new DirectoryInfo(Path.GetFullPath(vault)).Parent; parent != null; parent = parent.Parent)
        {
            var acl = parent.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            var owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner == null || !allowed.Contains(owner.Value))
                throw new IOException("Vault ancestor ownership requires an explicit offline service-owned migration.");
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0 &&
                    !allowed.Contains(rule.IdentityReference.Value) && (rule.FileSystemRights & dangerous) != 0)
                    throw new IOException("Vault ancestor permits non-administrator replacement or ACL changes; construction stopped.");
        }
    }
}
