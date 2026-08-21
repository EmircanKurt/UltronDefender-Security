using System;
using System.Runtime.InteropServices;

namespace AegisPC.Security.AntiEvasion
{
    public static class EtwBlindingDetector
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        public static bool IsEtwEventWritePatched()
        {
            try
            {
                IntPtr hNtdll = GetModuleHandle("ntdll.dll");
                if (hNtdll == IntPtr.Zero) return false;

                IntPtr pEtwWrite = GetProcAddress(hNtdll, "EtwEventWrite");
                if (pEtwWrite == IntPtr.Zero) return false;

                byte[] prelude = new byte[4];
                Marshal.Copy(pEtwWrite, prelude, 0, 4);

                // Patch patterns: 0xC3 (RET), 0xC2 0x14 0x00 (RET 0x14)
                if (prelude[0] == 0xC3 || (prelude[0] == 0xC2 && prelude[1] == 0x14))
                {
                    return true;
                }
            }
            catch { }

            return false;
        }
    }
}
