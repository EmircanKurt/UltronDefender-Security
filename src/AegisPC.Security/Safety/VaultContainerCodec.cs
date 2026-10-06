using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Security.Safety
{
    /// <summary>
    /// Karantina kasası kapsayıcı şifreleme ve çözme motoru.
    /// Yeni kayıtlar için doğrulanabilir V4 formatını yazar.
    /// V1, V2, V3 ve V4 formatlarını akış (streaming) ile çözer; eski kayıtların SHA doğrulaması motor tarafından yapılır.
    /// </summary>
    public static class VaultContainerCodec
    {
        public static readonly byte[] V3Header = Encoding.ASCII.GetBytes("AEGIS_VAULT_V3");
        public static readonly byte[] V4Header = Encoding.ASCII.GetBytes("AEGIS_VAULT_V4");
        public static readonly byte[] V1Header = Encoding.ASCII.GetBytes("AEGIS_VAULT_V1");
        public const string V2HeaderMagic = "ULTRON_QUAR_V2";

        /// <summary>V4: streaming AES-CBC with independently derived keys and encrypt-then-HMAC.
        /// The header and ciphertext are authenticated before any plaintext is emitted.</summary>
        public static async Task<(long PlainSize, string Sha256)> EncryptToVaultV4Async(
            Stream source, string targetPath, byte[] masterKey, CancellationToken cancellationToken = default)
        {
            byte[] encryptionKey = DeriveKey(masterKey, "Aegis.Vault.V4.Encryption");
            byte[] authenticationKey = DeriveKey(masterKey, "Aegis.Vault.V4.Authentication");
            try
            {
                var result = await EncryptToVaultV3Async(source, targetPath, encryptionKey, cancellationToken);
                await using var file = new FileStream(targetPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None, 81920, useAsync: true);
                file.Write(V4Header);
                using (var writer = new BinaryWriter(file, Encoding.UTF8, leaveOpen: true)) writer.Write(4);
                file.Position = 0;
                using var hmac = new HMACSHA256(authenticationKey);
                byte[] tag = await hmac.ComputeHashAsync(file, cancellationToken);
                await file.WriteAsync(tag, cancellationToken);
                file.Flush(flushToDisk: true);
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encryptionKey);
                CryptographicOperations.ZeroMemory(authenticationKey);
            }
        }

        private static byte[] DeriveKey(byte[] masterKey, string domain) =>
            HMACSHA256.HashData(masterKey, Encoding.UTF8.GetBytes(domain));

        /// <summary>
        /// Dosyayı AES-256-CBC ile akış halinde şifreleyerek V3 formatında kasaya yazar (64-bit uzunluk öneki).
        /// </summary>
        public static async Task<(long PlainSize, string Sha256)> EncryptToVaultV3Async(
            string sourcePath,
            string targetVaultPath,
            byte[] masterKey,
            CancellationToken cancellationToken = default)
        {
            await using var sourceFs = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
            return await EncryptToVaultV3Async(sourceFs, targetVaultPath, masterKey, cancellationToken);
        }

        public static async Task<(long PlainSize, string Sha256)> EncryptToVaultV3Async(
            Stream sourceFs, string targetVaultPath, byte[] masterKey, CancellationToken cancellationToken = default)
        {
            var iv = new byte[16];
            RandomNumberGenerator.Fill(iv);

            long plainSize;
            string sha256;

            {
                plainSize = sourceFs.Length;
                sha256 = Convert.ToHexString(await SHA256.HashDataAsync(sourceFs, cancellationToken)).ToLowerInvariant();
                sourceFs.Position = 0;

                await using (var outFs = new FileStream(targetVaultPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
                using (var bw = new BinaryWriter(outFs, Encoding.UTF8, leaveOpen: true))
                using (var aes = Aes.Create())
                {
                    aes.Key = masterKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    // Header V3: 14 byte Magic + 4 byte version (3) + 4 byte IV len + 16 byte IV + 8 byte plain size
                    bw.Write(V3Header);
                    bw.Write((int)3);
                    bw.Write(iv.Length);
                    bw.Write(iv);
                    bw.Write(plainSize); // 64-bit length prefix
                    bw.Flush();

                    using var encryptor = aes.CreateEncryptor();
                    await using var cryptoStream = new CryptoStream(outFs, encryptor, CryptoStreamMode.Write, leaveOpen: true);
                    await sourceFs.CopyToAsync(cryptoStream, 81920, cancellationToken).ConfigureAwait(false);
                    await cryptoStream.FlushFinalBlockAsync(cancellationToken).ConfigureAwait(false);
                    outFs.Flush(flushToDisk: true);
                }
            }

            return (plainSize, sha256);
        }

        /// <summary>
        /// Kasa kapsayıcısının şifresini çözer (V1, V2, V3 destekler) ve hedef akışa yazar.
        /// </summary>
        public static async Task<bool> DecryptVaultStreamAsync(
            string vaultFilePath,
            Stream outputStream,
            byte[] masterKey,
            CancellationToken cancellationToken = default)
        {
            if (!File.Exists(vaultFilePath)) return false;

            await using var fsIn = new FileStream(vaultFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
            if (fsIn.Length < 16) return false;

            // 1. Read first bytes to identify format
            byte[] leadBytes = new byte[32];
            int read = await fsIn.ReadAsync(leadBytes, 0, leadBytes.Length, cancellationToken);
            fsIn.Position = 0;

            if (read >= 14 && leadBytes.AsSpan(0, 14).SequenceEqual(V4Header))
                return await DecryptV4Async(fsIn, outputStream, masterKey, cancellationToken);

            if (read >= 14 && leadBytes.AsSpan(0, 14).SequenceEqual(V3Header))
            {
                return await DecryptV3Async(fsIn, outputStream, masterKey, cancellationToken);
            }

            if (read >= 14 && leadBytes.AsSpan(0, 14).SequenceEqual(V1Header))
            {
                return await DecryptV1Async(fsIn, outputStream, masterKey, cancellationToken);
            }

            // Check V2 string header: BinaryWriter writes 7-bit length prefix for "ULTRON_QUAR_V2" (length is 14 -> 0x0E)
            if (read >= 15 && leadBytes[0] == 14 && Encoding.UTF8.GetString(leadBytes, 1, 14) == V2HeaderMagic)
            {
                return await DecryptV2Async(fsIn, outputStream, masterKey, cancellationToken);
            }

            // Fallback: check GCM format (12-byte nonce, 16-byte tag)
            if (fsIn.Length >= 28 && fsIn.Length <= 50 * 1024 * 1024)
            {
                return await DecryptGcmAsync(fsIn, outputStream, masterKey, cancellationToken);
            }

            return false;
        }

        private static async Task<bool> DecryptV3Async(
            Stream fsIn,
            Stream outputStream,
            byte[] masterKey,
            CancellationToken cancellationToken, int expectedVersion = 3)
        {
            using var br = new BinaryReader(fsIn, Encoding.UTF8, leaveOpen: true);
            var header = br.ReadBytes(V3Header.Length);
            int version = br.ReadInt32();
            int ivLen = br.ReadInt32();
            if (version != expectedVersion || ivLen != 16) return false;

            byte[] iv = br.ReadBytes(ivLen);
            long expectedPlainLen = br.ReadInt64();
            if (expectedPlainLen < 0) return false;

            using var aes = Aes.Create();
            aes.Key = masterKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            await using var cryptoStream = new CryptoStream(fsIn, decryptor, CryptoStreamMode.Read, leaveOpen: true);
            await cryptoStream.CopyToAsync(outputStream, 81920, cancellationToken).ConfigureAwait(false);
            await outputStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            if (outputStream.CanSeek && outputStream.Length != expectedPlainLen)
            {
                return false;
            }

            return true;
        }

        private static async Task<bool> DecryptV4Async(FileStream input, Stream output, byte[] masterKey, CancellationToken ct)
        {
            // Header (46 bytes), at least one CBC block, and a 32-byte HMAC.
            if (input.Length < 94) return false;
            byte[] encryptionKey = DeriveKey(masterKey, "Aegis.Vault.V4.Encryption");
            byte[] authenticationKey = DeriveKey(masterKey, "Aegis.Vault.V4.Authentication");
            try
            {
                long authenticatedLength = input.Length - 32;
                using var limited = new LimitedReadStream(input, authenticatedLength);
                using var hmac = new HMACSHA256(authenticationKey);
                byte[] actual = await hmac.ComputeHashAsync(limited, ct);
                byte[] expected = new byte[32];
                await input.ReadExactlyAsync(expected, ct);
                if (!CryptographicOperations.FixedTimeEquals(actual, expected)) return false;
                input.Position = 0;
                return await DecryptV3Async(limited, output, encryptionKey, ct, expectedVersion: 4);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encryptionKey);
                CryptographicOperations.ZeroMemory(authenticationKey);
            }
        }

        // A bounded view prevents CryptoStream from treating the authentication tag as ciphertext.
        private sealed class LimitedReadStream : Stream
        {
            private readonly Stream _inner;
            private readonly long _length;
            public LimitedReadStream(Stream inner, long length) { _inner = inner; _length = length; }
            public override bool CanRead => true;
            public override bool CanSeek => true;
            public override bool CanWrite => false;
            public override long Length => _length;
            public override long Position { get => _inner.Position; set => _inner.Position = value; }
            public override int Read(byte[] buffer, int offset, int count) =>
                _inner.Read(buffer, offset, (int)Math.Min(count, Math.Max(0, _length - Position)));
            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
                _inner.ReadAsync(buffer[..(int)Math.Min(buffer.Length, Math.Max(0, _length - Position))], ct);
            public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
            public override void Flush() { }
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        private static async Task<bool> DecryptV2Async(
            Stream fsIn,
            Stream outputStream,
            byte[] masterKey,
            CancellationToken cancellationToken)
        {
            using var br = new BinaryReader(fsIn, Encoding.UTF8, leaveOpen: true);
            string magic = ReadBoundedLegacyString(br, 14);
            if (magic != V2HeaderMagic) return false;

            int ivLength = br.ReadInt32();
            if (ivLength != 16) return false;
            byte[] iv = br.ReadBytes(ivLength);

            string sha256 = ReadBoundedLegacyString(br, 128);
            if (sha256.Length != 64 || !IsHexDigest(sha256)) return false;
            int encryptedLength = br.ReadInt32();
            const int maximumLegacyCipherBytes = 64 * 1024 * 1024;
            if (encryptedLength > maximumLegacyCipherBytes)
                throw new InvalidDataException("LegacyMigrationRequired: V2 recovery content exceeds the supported 64 MiB budget.");
            if (encryptedLength <= 0 || encryptedLength % 16 != 0 || encryptedLength != fsIn.Length - fsIn.Position) return false;

            using var aes = Aes.Create();
            aes.Key = masterKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            await using var cryptoStream = new CryptoStream(fsIn, decryptor, CryptoStreamMode.Read, leaveOpen: true);
            await cryptoStream.CopyToAsync(outputStream, 81920, cancellationToken).ConfigureAwait(false);
            await outputStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            return true;
        }

        private static string ReadBoundedLegacyString(BinaryReader reader, int maximumBytes)
        {
            int byteCount = reader.Read7BitEncodedInt();
            if (byteCount < 0 || byteCount > maximumBytes)
                throw new InvalidDataException("LegacyMigrationRequired: V2 metadata exceeds its bounded format budget.");
            byte[] value = reader.ReadBytes(byteCount);
            if (value.Length != byteCount) throw new EndOfStreamException("Legacy V2 metadata was truncated.");
            return Encoding.UTF8.GetString(value);
        }

        private static bool IsHexDigest(string value)
        {
            foreach (char character in value)
                if (!Uri.IsHexDigit(character)) return false;
            return true;
        }

        private static async Task<bool> DecryptV1Async(
            Stream fsIn,
            Stream outputStream,
            byte[] masterKey,
            CancellationToken cancellationToken)
        {
            using var br = new BinaryReader(fsIn, Encoding.UTF8, leaveOpen: true);
            var header = br.ReadBytes(V1Header.Length);
            int ivLen = br.ReadInt32();
            if (ivLen != 16) return false;
            byte[] iv = br.ReadBytes(ivLen);
            int expectedPlainLen = br.ReadInt32();

            using var aes = Aes.Create();
            aes.Key = masterKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            await using var cryptoStream = new CryptoStream(fsIn, decryptor, CryptoStreamMode.Read, leaveOpen: true);
            await cryptoStream.CopyToAsync(outputStream, 81920, cancellationToken).ConfigureAwait(false);
            await outputStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            return true;
        }

        private static async Task<bool> DecryptGcmAsync(
            Stream fsIn,
            Stream outputStream,
            byte[] masterKey,
            CancellationToken cancellationToken)
        {
            try
            {
                byte[] raw = new byte[fsIn.Length];
                fsIn.Position = 0;
                int read = await fsIn.ReadAsync(raw, 0, raw.Length, cancellationToken);
                if (read < 28) return false;

                byte[] nonce = new byte[12];
                byte[] tag = new byte[16];
                byte[] cipherText = new byte[read - 28];

                Buffer.BlockCopy(raw, 0, nonce, 0, 12);
                Buffer.BlockCopy(raw, 12, tag, 0, 16);
                Buffer.BlockCopy(raw, 28, cipherText, 0, cipherText.Length);

                byte[] plainData = new byte[cipherText.Length];
                using (var aesGcm = new AesGcm(masterKey, 16))
                {
                    aesGcm.Decrypt(nonce, cipherText, tag, plainData);
                }

                // If GCM container wraps metadata + fileBytes binary structure
                if (plainData.Length > 8)
                {
                    using var ms = new MemoryStream(plainData);
                    using var br = new BinaryReader(ms);
                    int metaLen = br.ReadInt32();
                    if (metaLen > 0 && metaLen < plainData.Length - 8)
                    {
                        byte[] metaBytes = br.ReadBytes(metaLen);
                        int fileLen = br.ReadInt32();
                        if (fileLen > 0 && fileLen <= ms.Length - ms.Position)
                        {
                            byte[] fileBytes = br.ReadBytes(fileLen);
                            await outputStream.WriteAsync(fileBytes, 0, fileBytes.Length, cancellationToken);
                            return true;
                        }
                    }
                }

                await outputStream.WriteAsync(plainData, 0, plainData.Length, cancellationToken);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
