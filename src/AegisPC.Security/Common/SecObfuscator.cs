using System;
using System.Text;

namespace AegisPC.Security.Common
{
    public static class SecObfuscator
    {
        public static string Unmask(byte[] masked, byte key = 0x5A)
        {
            if (masked == null || masked.Length == 0) return string.Empty;
            byte[] unmasked = new byte[masked.Length];
            for (int i = 0; i < masked.Length; i++)
            {
                unmasked[i] = (byte)(masked[i] ^ key);
            }
            return Encoding.UTF8.GetString(unmasked);
        }
    }
}
