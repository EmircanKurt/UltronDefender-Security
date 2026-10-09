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
        public static bool IsStartMinimized { get; set; }
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
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to write to app log: {ex.Message}");
            }
        }

        protected override async void OnStartup(StartupEventArgs e)
        {
            // Scanner ILogger failures previously had no provider and vanished from runtime diagnostics.
            Serilog.Log.Logger = AegisPC.Infrastructure.Logging.SerilogConfiguration.Configure();
            var diagnosticAssembly = typeof(App).Assembly;
            var diagnosticVersion = diagnosticAssembly.GetName().Version;
            Serilog.Log.ForContext("SourceContext", "AegisPC.App.Startup")
                .Information("Application diagnostic session started with module {ModuleId}, version {VersionMajor}.{VersionMinor}.{VersionBuild}.",
                    diagnosticAssembly.ManifestModule.ModuleVersionId, diagnosticVersion?.Major ?? 0,
                    diagnosticVersion?.Minor ?? 0, diagnosticVersion?.Build ?? 0);
            Log("=== AegisPC App Startup Begin ===");
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            DispatcherUnhandledException += App_DispatcherUnhandledException;
            TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;

            IsStartMinimized = Array.Exists(e.Args ?? Array.Empty<string>(), arg =>
                arg.Equals("--minimized", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("/minimized", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("-minimized", StringComparison.OrdinalIgnoreCase));
            // Keep interactive startup visible a little longer; background startup must not flash a window.
            SplashWindow? splash = null;
            var splashClock = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                if (!IsStartMinimized)
                {
                splash = new SplashWindow();
                splash.Show();
                }
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
                // Schema readiness precedes any repositories, event subscriptions or protection-dependent view models.
                await ServiceProvider.GetRequiredService<AegisPC.Contracts.Services.IDatabaseService>().InitializeAsync();
                await ServiceProvider.GetRequiredService<AegisPC.Contracts.Services.ISettingsService>().LoadAsync();
                _ = ServiceProvider.GetRequiredService<AegisPC.App.Services.UltronAiServicePreferenceSync>();

                // Eagerly resolve ScanViewModel so it attaches to IScanCoordinatorService events immediately from boot
                try
                {
                    _ = ServiceProvider.GetService<AegisPC.App.ViewModels.ScanViewModel>();
                    Log("2.1. ScanViewModel eagerly resolved.");
                }
                catch (Exception ex)
                {
                    Log($"[WARN] ScanViewModel eager resolve failed: {ex.Message}");
                }


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

                bool startMinimized = IsStartMinimized;

                // DI konteyneri hazırlandıktan sonra splash penceresini 250 ms fade-out ile kapat
                try
                {
                    if (splash != null)
                    {
                        var elapsed = splashClock.Elapsed;
                        var minDuration = TimeSpan.FromMilliseconds(2600);
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
                            await splash.FadeOutAndCloseAsync(350);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Serilog.Log.Warning(ex, "Splash window close failed.");
                    try { splash?.Close(); } catch (Exception closeEx) { Serilog.Log.Warning(closeEx, "Fallback splash.Close() failed."); }
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

                    // Eagerly resolve ScanViewModel so it attaches to IScanCoordinatorService events immediately from boot
                    var scanVm = ServiceProvider.GetService<AegisPC.App.ViewModels.ScanViewModel>();

                    // Initialize System Tray Icon First
                    var trayService = ServiceProvider.GetService<AegisPC.App.Services.ISystemTrayService>();
                    trayService?.Initialize();

                    if (toastService != null)
                    {
                        if (bgService != null)
                        {
                            bgService.OnNotificationRaised += (title, msg) => toastService.ShowToast(title, msg);
                        }

                        if (behaviorEngine != null)
                        {
                            behaviorEngine.OnThreatContained += (proc, threat) =>
                            {
                                toastService.ShowToast($"⚠️ Davranış Uyarısı: {threat}", $"'{proc}' için güvenlik olayı kaydedildi. Müdahalenin ayrıntılarını Olay Merkezinden inceleyin.", "Warning");
                            };
                        }

                        // ScanViewModel owns the final scan notification. A second startup
                        // subscription would count heuristic findings as threats and duplicate it.

                        // Start Core Real-Time Progressive Protection Engine
                        var realTimeEngine = ServiceProvider.GetService<AegisPC.Security.RealTime.IRealTimeProtectionEngine>();
                        if (realTimeEngine != null)
                        {
                            realTimeEngine.OnNotificationRaised += (title, msg, type) =>
                            {
                                toastService?.ShowToast(title, msg, type);
                            };
                        }

                        var ransomwareEngine = ServiceProvider.GetService<AegisPC.Security.RealTime.IRansomwareProtectionEngine>();
                        if (ransomwareEngine != null)
                        {
                            ransomwareEngine.OnRansomwareAttemptDetected += (s, ev) =>
                            {
                                toastService?.ShowToast(
                                    "⚠️ Şüpheli Şifreleme Uyarısı",
                                    ev.ProcessTerminated
                                        ? $"Süreç sonlandırıldı. İncelenen dosya: '{System.IO.Path.GetFileName(ev.OffendingFilePath)}'. Dosya karantinası bu olayda doğrulanmadı."
                                        : $"Şüpheli etkinlik kaydedildi: '{System.IO.Path.GetFileName(ev.OffendingFilePath)}'. Müdahale sonucu doğrulanmadı; olayı inceleyin.",
                                    "Warning");
                            };
                        }

                        var etwMonitor = ServiceProvider.GetService<AegisPC.Contracts.Services.IEtwProcessMonitorService>();
                        if (etwMonitor != null)
                        {
                            var lineageTracker = ServiceProvider.GetService<AegisPC.Contracts.Behavior.IProcessLineageTracker>();

                            etwMonitor.ThreatDetected += (alert) =>
                            {
                                toastService?.ShowToast(
                                    $"⚠️ Süreç Komutu Uyarısı: {alert.ThreatName}",
                                    $"Şüpheli komut algılandı (PID: {alert.ProcessId}). Bu bildirim süreç sonlandırmasını doğrulamaz.\nKomut: {alert.CommandLine}",
                                    "Warning");
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

                        }

                        if (ipcClient != null)
                        {
                            ipcClient.ThreatDetected += (threat) =>
                            {
                                if (!AegisPC.Core.Models.FindingVisibilityPolicy.IsVisible(threat.SoftwareClass,
                                    threat.SoftwareClassification, threat.SHA256, threat.RuleSetVersion, threat.InspectionComplete,
                                    threat.CoverageLimitations.Length != 0, threat.PolicyBypassed, threat.HasIndependentMalwareEvidence,
                                    threat.RiskLevel, ServiceProvider?.GetService<AegisPC.Contracts.Services.ISettingsService>()?.GetSetting("ShowPotentiallyUnwantedToolFindings", false) == true)) return;
                                string label = threat.IsObservationOnly ? "Güvenlik gözlemi" : "Güvenlik bulgusu";
                                toastService.ShowToast($"{label}: {threat.ThreatName}", $"Dosya: {threat.FilePath}\nİşlem: {threat.ActionTaken}", "Warning");
                            };
                            _ = ipcClient.ConnectAsync();
                            Log("Protection engines are service-owned; UI connected through IPC without starting duplicate local watchers.");
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
                try { splash?.Close(); } catch (Exception closeError) { Serilog.Log.Warning(closeError, "Startup failure splash cleanup failed."); }
                Shutdown(1);
                return;
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
                        // GC.Collect kaldırıldı: .NET 8 Server GC bu işi otomatik yönetir, manuel GC WPF UI thread'ini dondurur
                        // GC.Collect(2, GCCollectionMode.Optimized, blocking: false);

                        // Kullanılmayan fiziksel sayfaları Windows çekirdeğine geri ver
                        try
                        {
                            SetProcessWorkingSetSize(System.Diagnostics.Process.GetCurrentProcess().Handle, (IntPtr)(-1), (IntPtr)(-1));
                        }
                        catch (Exception ex)
                        {
                            Log($"[TRACE] SetProcessWorkingSetSize error: {ex.Message}");
                        }
                    }
                    else if (managedMemory > 200 * 1024 * 1024)
                    {
                        // GC.Collect(1, GCCollectionMode.Optimized, false, false);
                    }
                }
                catch (Exception ex)
                {
                    Log($"[ERROR] Memory watchdog exception: {ex.Message}");
                }
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
            finally
            {
                Serilog.Log.CloseAndFlush();
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
            catch (Exception ex)
            {
                Log($"[CRITICAL] Error displaying dispatcher unhandled exception: {ex.Message}");
            }
            finally
            {
                e.Handled = true;
            }
        }

        private void TaskScheduler_UnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            try
            {
                Log($"[CRITICAL] Unobserved Task Exception: {e.Exception}");
                Serilog.Log.Error(e.Exception, "Ultron Defender arka plan görevinde (Task) yakalanmamış istisna.");
                e.SetObserved();
            }
            catch (Exception ex)
            {
                Log($"[CRITICAL] Error handling unobserved task exception: {ex.Message}");
            }
        }
    }
}
