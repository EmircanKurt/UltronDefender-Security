using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    public class SignatureVerifier : ISignatureVerifier
    {
        private readonly ILogger<SignatureVerifier>? _logger;

        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(
            IntPtr hwnd,
            [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
            IntPtr pWVTData);

        public SignatureVerifier(ILogger<SignatureVerifier>? logger = null)
        {
            _logger = logger;
        }

        public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (!File.Exists(filePath))
            {
                return Task.FromResult(new SignatureInfo
                {
                    IsSigned = false,
                    IsValid = false
                });
            }

            try
            {
                // 1. Try embedded Authenticode X509 certificate extraction
                try
                {
                    using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
                    bool isChainValid = false;

                    using (var chain = new X509Chain())
                    {
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        isChainValid = chain.Build(cert);
                    }

                    var publisher = cert.GetNameInfo(X509NameType.SimpleName, false);
                    var issuer = cert.GetNameInfo(X509NameType.SimpleName, true);

                    return Task.FromResult(new SignatureInfo
                    {
                        IsSigned = true,
                        IsValid = isChainValid,
                        Publisher = publisher,
                        Issuer = issuer,
                        SerialNumber = cert.SerialNumber,
                        Thumbprint = cert.Thumbprint,
                        ValidFrom = cert.NotBefore,
                        ValidTo = cert.NotAfter,
                        SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName
                    });
                }
                catch
                {
                    // Embedded certificate not present, fallback to WinVerifyTrust (Catalog signed)
                }

                // 2. Try WinVerifyTrust (handles Windows Catalog signed system files)
                bool isWinTrustValid = CheckWinVerifyTrust(filePath);
                if (isWinTrustValid)
                {
                    bool isSystem = PathHelper.IsSystemPath(filePath);
                    return Task.FromResult(new SignatureInfo
                    {
                        IsSigned = true,
                        IsValid = true,
                        Publisher = isSystem ? "Microsoft Windows" : "Doğrulanmış Windows Kataloğu",
                        Issuer = "Microsoft Windows Production PCA",
                        SignatureAlgorithm = "SHA256"
                    });
                }

                return Task.FromResult(new SignatureInfo
                {
                    IsSigned = false,
                    IsValid = false
                });
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error verifying signature for {Path}", filePath);
                return Task.FromResult(new SignatureInfo
                {
                    IsSigned = false,
                    IsValid = false
                });
            }
        }

        private static bool CheckWinVerifyTrust(string filePath)
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            IntPtr pWVTData = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA)));

            try
            {
                Marshal.StructureToPtr(fileInfo, pFileInfo, false);

                var wvtData = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = 2, // WTD_UI_NONE
                    fdwRevocationChecks = 0, // WTD_REVOKE_NONE
                    dwUnionChoice = 1, // WTD_CHOICE_FILE
                    pFile = pFileInfo,
                    dwStateAction = 0, // WTD_STATEACTION_IGNORE
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = null,
                    dwProvFlags = 0x00000040 | 0x00000080, // WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };

                Marshal.StructureToPtr(wvtData, pWVTData, false);

                int result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pWVTData);
                return result == 0; // ERROR_SUCCESS
            }
            catch
            {
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(pFileInfo);
                Marshal.FreeHGlobal(pWVTData);
            }
        }
    }
}
