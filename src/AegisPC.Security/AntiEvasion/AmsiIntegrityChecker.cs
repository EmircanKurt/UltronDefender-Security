using System;
using System.Runtime.InteropServices;

namespace AegisPC.Security.AntiEvasion
{
    public static class AmsiIntegrityChecker
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("kernel32.dll")]
        private static extern bool FreeLibrary(IntPtr hModule);

        public static bool IsAmsiPatched()
        {
            try
            {
                IntPtr hAmsi = LoadLibrary("amsi.dll");
                if (hAmsi == IntPtr.Zero) return false;

                try
                {
                    IntPtr pScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
                    if (pScanBuffer == IntPtr.Zero) return false;

                    byte[] prelude = new byte[6];
                    Marshal.Copy(pScanBuffer, prelude, 0, 6);

                    // Patch patterns: 0xC3 (RET), 0xB8 0x57 (MOV EAX, 0x80070057)
                    if (prelude[0] == 0xC3 || (prelude[0] == 0xB8 && prelude[1] == 0x57))
                    {
                        return true;
                    }
                }
                finally
                {
                    FreeLibrary(hAmsi);
                }
            }
            catch { }

            return false;
        }
    }
}
