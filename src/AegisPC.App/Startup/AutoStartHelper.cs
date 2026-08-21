using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace AegisPC.App.Startup
{
    public static class AutoStartHelper
    {
        private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string AppName = "UltronDefender";

        /// <summary>
        /// Windows başlangıcında otomatik ve arka planda (--minimized) başlamasını sağlar.
        /// </summary>
        public static void EnsureAutoStartRegistered()
        {
            try
            {
                var exePath = Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                {
                    exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AegisPC.exe");
                }

                if (File.Exists(exePath))
                {
                    using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
                    if (key != null)
                    {
                        var commandValue = $"\"{exePath}\" --minimized";
                        key.SetValue(AppName, commandValue);
                    }
                }
            }
            catch { }
        }

        public static bool IsAutoStartEnabled()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
                return key?.GetValue(AppName) != null;
            }
            catch
            {
                return false;
            }
        }

        public static void SetAutoStart(bool enable)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
                if (key != null)
                {
                    if (enable)
                    {
                        EnsureAutoStartRegistered();
                    }
                    else
                    {
                        key.DeleteValue(AppName, false);
                    }
                }
            }
            catch { }
        }
    }
}
