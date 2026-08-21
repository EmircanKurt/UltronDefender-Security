using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;

namespace AegisPC.Uninstaller
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void OnCancelClick(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private async void OnUninstallClick(object sender, RoutedEventArgs e)
        {
            bool cleanShortcuts = ChkCleanShortcuts.IsChecked ?? true;
            bool cleanVault = ChkCleanQuarantine.IsChecked ?? true;

            StepConfirmation.Visibility = Visibility.Collapsed;
            PnlButtonsStep1.Visibility = Visibility.Collapsed;
            StepProgress.Visibility = Visibility.Visible;

            await Task.Run(async () =>
            {
                // 1. Stop all processes
                UpdateStatus("Çalışan güvenlik süreçleri sonlandırılıyor...");
                try
                {
                    var targets = new[] { "ultrondefender", "aegispc", "ultron defender" };
                    var procs = Process.GetProcesses();
                    foreach (var p in procs)
                    {
                        try
                        {
                            var name = p.ProcessName.ToLowerInvariant();
                            foreach (var t in targets)
                            {
                                if (name.Contains(t) && p.Id != Process.GetCurrentProcess().Id)
                                {
                                    p.Kill();
                                    p.WaitForExit(2000);
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }

                await Task.Delay(600);

                // 2. Clean Registry Shell Context Menu & AutoRun
                UpdateStatus("Sağ tık menüsü ve sistem başlangıç kayıtları temizleniyor...");
                try
                {
                    using (var r = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\*", true))
                    {
                        r?.DeleteSubKeyTree("shell\\UltronDefenderScan", false);
                    }
                    using (var r = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\Directory", true))
                    {
                        r?.DeleteSubKeyTree("shell\\UltronDefenderScan", false);
                    }
                    using (var r = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\Directory\Background", true))
                    {
                        r?.DeleteSubKeyTree("shell\\UltronDefenderScan", false);
                    }
                    using (var r = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        r?.DeleteValue("UltronDefender", false);
                        r?.DeleteValue("AegisPC", false);
                    }
                }
                catch { }

                await Task.Delay(600);

                // 3. Remove shortcuts
                if (cleanShortcuts)
                {
                    UpdateStatus("Masaüstü ve Başlat Menüsü kısayolları kaldırılıyor...");
                    try
                    {
                        var userDesktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                        var commonDesktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
                        var userPrograms = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
                        var commonPrograms = Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);

                        var shortcutDirs = new[] { userDesktop, commonDesktop, userPrograms, commonPrograms };
                        var names = new[]
                        {
                            "Ultron Defender Total Security.lnk",
                            "Ultron Defender Security.lnk",
                            "UltronDefender.lnk",
                            "AegisPC.lnk"
                        };

                        foreach (var dir in shortcutDirs)
                        {
                            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;

                            foreach (var name in names)
                            {
                                var file = Path.Combine(dir, name);
                                if (File.Exists(file))
                                {
                                    try { File.Delete(file); } catch { }
                                }
                            }

                            var ultronGroup = Path.Combine(dir, "Ultron Defender Total Security");
                            if (Directory.Exists(ultronGroup))
                            {
                                try { Directory.Delete(ultronGroup, true); } catch { }
                            }
                        }
                    }
                    catch { }
                }

                await Task.Delay(600);

                // 4. Clean Vault & Settings if requested
                if (cleanVault)
                {
                    UpdateStatus("Karantina Kasası ve ayar kalıntıları temizleniyor...");
                    try
                    {
                        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                        var folders = new[]
                        {
                            Path.Combine(appData, "AegisPC"),
                            Path.Combine(appData, "UltronDefender"),
                            Path.Combine(localAppData, "AegisPC"),
                            Path.Combine(localAppData, "UltronDefender")
                        };

                        foreach (var f in folders)
                        {
                            if (Directory.Exists(f))
                            {
                                try { Directory.Delete(f, true); } catch { }
                            }
                        }
                    }
                    catch { }
                }

                // 5. Trigger silent Inno Setup uninstaller if present
                try
                {
                    var baseDir = AppDomain.CurrentDomain.BaseDirectory;
                    var uninsExe = Path.Combine(baseDir, "unins000.exe");
                    if (File.Exists(uninsExe))
                    {
                        UpdateStatus("Windows Program Kaldırma kaydı güncelleniyor...");
                        var psi = new ProcessStartInfo
                        {
                            FileName = uninsExe,
                            Arguments = "/SILENT /VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
                            UseShellExecute = true,
                            WindowStyle = ProcessWindowStyle.Hidden
                        };
                        var uninsProc = Process.Start(psi);
                        uninsProc?.WaitForExit(5000);
                    }
                }
                catch { }

                await Task.Delay(800);
            });

            StepProgress.Visibility = Visibility.Collapsed;
            StepFarewell.Visibility = Visibility.Visible;
            PnlButtonsStep3.Visibility = Visibility.Visible;
        }

        private void UpdateStatus(string status)
        {
            Dispatcher.Invoke(() =>
            {
                TxtStatus.Text = status;
            });
        }

        private void OnCloseClick(object sender, RoutedEventArgs e)
        {
            try
            {
                var baseDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\', '/');
                // If installed in Program Files or custom folder (not source code folder), schedule self-directory removal
                if (!baseDir.ToLowerInvariant().Contains("gemini virüs program") && !baseDir.ToLowerInvariant().Contains("src"))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c timeout /t 1 /nobreak > nul & rmdir /s /q \"{baseDir}\"",
                        WindowStyle = ProcessWindowStyle.Hidden,
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                }
            }
            catch { }

            Close();
        }
    }
}