using System;
using System.IO;
using System.Windows;
using System.Threading.Tasks;
using System.Windows.Threading;
using AegisPC.App.Startup;
using AegisPC.App.Views;
using Microsoft.Extensions.DependencyInjection;
using Wpf.Ui;

namespace AegisPC.App
{
    public partial class App : System.Windows.Application
    {
        public static IServiceProvider? ServiceProvider { get; private set; }
        private static readonly string LogFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisPC", "Logs", "aegis_debug.log");

        private static void Log(string msg)
        {
            try
            {
                var dir = Path.GetDirectoryName(LogFile);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                File.AppendAllText(LogFile, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {msg}\r\n");
            }
            catch { }
        }

        protected override async void OnStartup(StartupEventArgs e)
        {
            Log("=== AegisPC App Startup Begin ===");
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            DispatcherUnhandledException += App_DispatcherUnhandledException;

            // GÖREV 2: 1.5-2 sn'lik koyu temalı açılış (splash) animasyonu
            SplashWindow? splash = null;
            DateTime splashStart = DateTime.UtcNow;
            try
            {
                splash = new SplashWindow();
                splash.Show();
            }
            catch (Exception ex)
            {
                Log($"[WARN] SplashWindow gösterilemedi: {ex.Message}");
                Serilog.Log.Warning(ex, "SplashWindow başlatılırken hata oluştu.");
            }

            try
            {
                Log("1. Registering services...");
                var serviceCollection = new ServiceCollection();
                ServiceRegistration.RegisterServices(serviceCollection);
                ServiceProvider = serviceCollection.BuildServiceProvider();
                Log("2. Services registered successfully.");


                // Register Windows Startup entry & Antivirus Security Center Registration
                try
                {
                    AutoStartHelper.EnsureAutoStartRegistered();
                    var secReg = ServiceProvider.GetService<AegisPC.Infrastructure.IWindowsSecurityRegistrationService>();
                    secReg?.RegisterAsSecurityProvider();
                }
                catch (Exception ex)
                {
                    Log($"[WARN] AutoStart / SecurityRegistration failed: {ex.Message}");
                }

                // Apply Saved UI Theme (Dark or Light)
                try
                {
                    AegisPC.App.Services.AppThemeManager.ApplyTheme(AegisPC.App.Services.AppThemeManager.CurrentTheme);
                }
                catch (Exception ex)
                {
                    Log($"[WARN] Theme application failed: {ex.Message}");
                }

                Log("3. Resolving MainWindow...");
                var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
                MainWindow = mainWindow;

                bool startMinimized = false;
                if (e.Args != null)
                {
                    foreach (var arg in e.Args)
                    {
                        if (arg.Equals("--minimized", StringComparison.OrdinalIgnoreCase) || 
                            arg.Equals("/minimized", StringComparison.OrdinalIgnoreCase) ||
                            arg.Equals("-minimized", StringComparison.OrdinalIgnoreCase))
                        {
                            startMinimized = true;
                            break;
                        }
                    }
                }

                // DI konteyneri hazırlandıktan sonra splash penceresini 250 ms fade-out ile kapat
                try
                {
                    if (splash != null)
                    {
                        var elapsed = DateTime.UtcNow - splashStart;
                        var minDuration = TimeSpan.FromMilliseconds(1600);
                        if (elapsed < minDuration)
                        {
                            await Task.Delay(minDuration - elapsed);
                        }

                        if (startMinimized)
                        {
                            splash.Close();
                        }
                        else
                        {
                            await splash.FadeOutAndCloseAsync(250);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Serilog.Log.Warning(ex, "Splash penceresi kapatılırken hata oluştu.");
                    try { splash?.Close(); } catch { }
                }

                if (!startMinimized)
                {
                    Log("4. Showing MainWindow...");
                    mainWindow.Show();
                    Log("5. MainWindow shown successfully.");
                }
                else
                {
                    Log("4. Starting in background (System Tray only)...");
                }

                // Start real-time download and background protection
                try
                {
                    var bgService = ServiceProvider.GetService<AegisPC.Security.RealTime.IBackgroundProtectionService>();
                    var toastService = ServiceProvider.GetService<AegisPC.Contracts.Services.IWindowsToastNotificationService>();
                    var behaviorEngine = ServiceProvider.GetService<AegisPC.Contracts.Services.IBehaviorEngine>();
                    var ipcClient = ServiceProvider.GetService<AegisPC.ServiceContracts.IServiceIpcClient>();
                    var scanCoordinator = ServiceProvider.GetService<AegisPC.Contracts.Services.IScanCoordinatorService>();

                    // Initialize System Tray Icon First
                    var trayService = ServiceProvider.GetService<AegisPC.App.Services.ISystemTrayService>();
                    trayService?.Initialize();

                    if (toastService != null)
                    {
                        if (bgService != null)
                        {
                            bgService.OnNotificationRaised += (title, msg) => toastService.ShowToast(title, msg);
                            bgService.StartProtection();
                        }

                        if (behaviorEngine != null)
                        {
                            behaviorEngine.OnThreatContained += (proc, threat) =>
                            {
                                toastService.ShowToast($"🚨 Tehdit Engellendi: {threat}", $"Zararlı davranış sergileyen '{proc}' süreci sonlandırıldı ve dosya karantinaya alındı.", "Error");
                            };
                        }

                        if (scanCoordinator != null)
                        {
                            scanCoordinator.ScanCompleted += (result) =>
                            {
                                // Otomatik (zamanlanmış) taramalar BackgroundProtectionService tarafından
                                // yalnızca YENİ bulgu varsa bildirilir; burada çift bildirim yapma.
                                if (AegisPC.Security.RealTime.BackgroundProtectionService.IsAutomaticScanInProgress) return;

                                int activeCount = result.Findings.Count(f => f.Status == AegisPC.Core.Enums.FindingStatus.Active && !f.IsAllowlisted);
                                if (activeCount > 0)
                                {
                                    toastService.ShowToast(
                                        "🚨 Ultron Defender: Tehdit Tespit Edildi!",
                                        $"{result.ScanType} taraması tamamlandı: {activeCount} adet riskli tehdit bulundu. Detayları görmek için tıklayın.",
                                        "Warning");
                                }
                            };
                        }

                        // Start Core Real-Time Progressive Protection Engine
                        var realTimeEngine = ServiceProvider.GetService<AegisPC.Security.RealTime.IRealTimeProtectionEngine>();
                        if (realTimeEngine != null)
                        {
                            realTimeEngine.Start();
                            realTimeEngine.OnNotificationRaised += (title, msg, type) =>
                            {
                                toastService?.ShowToast(title, msg, type);
                            };
                        }

                        var ransomwareEngine = ServiceProvider.GetService<AegisPC.Security.RealTime.IRansomwareProtectionEngine>();
                        if (ransomwareEngine != null)
                        {
                            ransomwareEngine.StartShield();
                            ransomwareEngine.OnRansomwareAttemptDetected += (s, ev) =>
                            {
                                toastService?.ShowToast(
                                    "🚨 Fidye Saldırısı Engellendi!",
                                    $"Şüpheli şifreleme girişimi durduruldu: '{System.IO.Path.GetFileName(ev.OffendingFilePath)}'",
                                    "Error");
                            };
                        }

                        var etwMonitor = ServiceProvider.GetService<AegisPC.Contracts.Services.IEtwProcessMonitorService>();
                        if (etwMonitor != null)
                        {
                            var lineageTracker = ServiceProvider.GetService<AegisPC.Contracts.Behavior.IProcessLineageTracker>();

                            etwMonitor.ThreatDetected += (alert) =>
                            {
                                toastService?.ShowToast(
                                    $"🚨 ETW Tehdit Engellendi: {alert.ThreatName}",
                                    $"Zararlı komut çalıştıran süreç durduruldu (PID: {alert.ProcessId})\nKomut: {alert.CommandLine}",
                                    "Danger");
                            };

                            // P0 Telemetry Pipeline: Wire Process Creation -> DAG Lineage Tree -> Behavior Engine
                            etwMonitor.ProcessCreated += async (procEvent) =>
                            {
                                try
                                {
                                    // 1. Register in Process Lineage DAG tree
                                    lineageTracker?.RegisterProcess(new AegisPC.Contracts.Behavior.ProcessNode
                                    {
                                        Pid = procEvent.ProcessId,
                                        ParentPid = procEvent.ParentProcessId,
                                        ProcessName = procEvent.ImageFileName,
                                        CommandLine = procEvent.CommandLine,
                                        StartTimeUtc = procEvent.Timestamp
                                    });

                                    // 2. Check for suspicious parent-child spawn (LOLBin / Macro / Browser RCE / Fake system processes)
                                    bool isSuspiciousSpawn = false;
                                    string? anomalyReason = null;
                                    if (lineageTracker != null && procEvent.ParentProcessId > 0)
                                    {
                                        isSuspiciousSpawn = lineageTracker.IsSuspiciousParentChild(procEvent.ParentProcessId, procEvent.ProcessId, out anomalyReason);
                                    }

                                    // 3. Forward to BehaviorEngine for dynamic session and multi-stage evaluation
                                    if (behaviorEngine != null)
                                    {
                                        var bEvent = new AegisPC.Core.Models.BehaviorEvent
                                        {
                                            ProcessId = procEvent.ProcessId,
                                            ParentProcessId = procEvent.ParentProcessId,
                                            ProcessName = procEvent.ImageFileName,
                                            CommandLine = procEvent.CommandLine,
                                            EventType = isSuspiciousSpawn ? AegisPC.Core.Models.BehaviorEventType.ChildProcessSpawn : AegisPC.Core.Models.BehaviorEventType.ProcessSpawn,
                                            TargetResource = procEvent.CommandLine,
                                            Details = isSuspiciousSpawn ? $"Şüpheli Süreç Türetmesi: {anomalyReason}" : "Süreç başlatıldı",
                                            RiskWeight = isSuspiciousSpawn ? 45.0 : 5.0,
                                            Timestamp = procEvent.Timestamp
                                        };

                                        await behaviorEngine.ProcessEventAsync(bEvent);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log($"[ERROR] ETW process event handling error: {ex.Message}");
                                }
                            };

                            etwMonitor.Start();
                        }

                        if (ipcClient != null)
                        {
                            ipcClient.ThreatDetected += (threat) =>
                            {
                                toastService.ShowToast($"🚨 Arka Plan Tehdit Uyarısı: {threat.ThreatName}", $"Dosya: {threat.FilePath}\nİşlem: {threat.ActionTaken}", "Warning");
                            };
                            _ = ipcClient.ConnectAsync();
                        }
                    }

                    // Strict Memory Watchdog: 2 GB Mutlak RAM Tavanı Bekçisi
                    StartMemoryWatchdog();
                }
                catch (Exception ex)
                {
                    Log($"Background protection startup warning: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Log($"CRITICAL STARTUP ERROR: {ex}");
                MessageBox.Show($"Uygulama başlatılırken bir hata oluştu:\n\n{ex.Message}\n\nDetay:\n{ex.StackTrace}", 
                    "Ultron Defender Total Security - Başlatma Hatası", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            base.OnStartup(e);
            Log("=== OnStartup Completed ===");
        }

        #region Strict 2GB Memory Watchdog & Working Set Trimming
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr dwMinimumWorkingSetSize, IntPtr dwMaximumWorkingSetSize);

        private static System.Threading.Timer? _memoryTimer;

        private static void StartMemoryWatchdog()
        {
            _memoryTimer = new System.Threading.Timer(_ =>
            {
                try
                {
                    long managedMemory = GC.GetTotalMemory(forceFullCollection: false);
                    long workingSet = System.Diagnostics.Process.GetCurrentProcess().WorkingSet64;

                    // 1. Yönetilen bellek 400 MB'ı aşarsa veya fiziksel RAM 1 GB'ı geçerse optimize toplama
                    if (managedMemory > 400 * 1024 * 1024 || workingSet > 1024 * 1024 * 1024)
                    {
                        GC.Collect(2, GCCollectionMode.Optimized, blocking: false);

                        // Kullanılmayan fiziksel sayfaları Windows çekirdeğine geri ver
                        try
                        {
                            SetProcessWorkingSetSize(System.Diagnostics.Process.GetCurrentProcess().Handle, (IntPtr)(-1), (IntPtr)(-1));
                        }
                        catch { }
                    }
                    else if (managedMemory > 200 * 1024 * 1024)
                    {
                        GC.Collect(1, GCCollectionMode.Optimized, false, false);
                    }
                }
                catch { }
            }, null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
        }
        #endregion

        protected override void OnExit(ExitEventArgs e)
        {
            Log($"=== Ultron Defender App Shut down with code {e.ApplicationExitCode} ===");
            try
            {
                _memoryTimer?.Dispose();
                _memoryTimer = null;

                var trayService = ServiceProvider?.GetService<AegisPC.App.Services.ISystemTrayService>();
                trayService?.Dispose();

                if (ServiceProvider is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }
            catch (Exception ex)
            {
                Log($"[WARN] Service cleanup warning: {ex.Message}");
            }
            base.OnExit(e);
        }

        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            Log($"AppDomain Unhandled Exception: {e.ExceptionObject}");
            if (e.ExceptionObject is Exception ex)
            {
                MessageBox.Show($"Kritik Hata:\n{ex.Message}", "Ultron Defender Total Security - Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static DateTime _lastDispatcherErrorTime = DateTime.MinValue;
        private static int _consecutiveDispatcherErrors = 0;

        private void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            try
            {
                Log($"Dispatcher Unhandled Exception: {e.Exception}");
                var now = DateTime.UtcNow;

                // Anti-flood / anti-cascade guard: If errors occur rapidly in layout loops, debounce
                if ((now - _lastDispatcherErrorTime).TotalSeconds < 3.0)
                {
                    _consecutiveDispatcherErrors++;
                    if (_consecutiveDispatcherErrors == 3)
                    {
                        MessageBox.Show(
                            "Arayüz bileşenlerinde ardışık hata tespit edildi. Diğer hata pencereleri engellendi ve ayrıntılar günlüğe (aegis_debug.log) yazıldı.",
                            "Ultron Defender Total Security - Arayüz Bildirimi",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                    }
                    e.Handled = true;
                    return;
                }

                _lastDispatcherErrorTime = now;
                _consecutiveDispatcherErrors = 1;

                MessageBox.Show($"Arayüz Hatası:\n{e.Exception?.Message}\n\nDetay: {e.Exception?.InnerException?.Message}", 
                    "Ultron Defender Total Security - Arayüz Hatası", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            catch { }
            finally
            {
                e.Handled = true;
            }
        }
    }
}
