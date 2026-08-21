using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Windows;

namespace AegisPC.App
{
    public static class Program
    {
        private static readonly string MutexName = @"Local\UltronDefender_SingleInstance_" + Environment.UserName;
        private static readonly string PipeName = "UltronDefender_Activate_Pipe_" + Environment.UserName;
        private static readonly string EventName = @"Local\UltronDefender_Activate_Event_" + Environment.UserName;

        private static Mutex? _mutex;
        private static EventWaitHandle? _activateEvent;
        private static Thread? _listenerThread;
        private static Thread? _pipeThread;
        private static volatile bool _running = true;
        public static string? PendingStartupScanPath { get; set; }

        [STAThread]
        public static void Main(string[] args)
        {
            AppDomain.CurrentDomain.AssemblyResolve += (sender, resolveArgs) =>
            {
                try
                {
                    var assemblyNameObj = new System.Reflection.AssemblyName(resolveArgs.Name);
                    string assemblyName = assemblyNameObj.Name + ".dll";
                    string appDir = AppDomain.CurrentDomain.BaseDirectory;
                    string assemblyPath = Path.Combine(appDir, assemblyName);
                    if (File.Exists(assemblyPath))
                    {
                        return System.Reflection.Assembly.LoadFrom(assemblyPath);
                    }
                }
                catch { }
                return null;
            };

            string? targetScanPath = ParseScanArgument(args);

            bool createdNew;
            try
            {
                _mutex = new Mutex(true, MutexName, out createdNew);
            }
            catch
            {
                createdNew = true;
            }

            if (!createdNew)
            {
                // İkincil süreç: Çalışan ana programa 'Tara' veya 'Pencereyi Öne Getir' komutu gönder
                SignalRunningInstance(targetScanPath);
                return;
            }

            PendingStartupScanPath = targetScanPath;

            // Birincil süreç: Named Pipe ve Event dinleyicilerini başlat
            StartActivationListeners();

            // Windows Explorer Sağ Tık Menüsü Kaydı (🛡️ Ultron Defender ile Tara)
            Services.ShellContextMenuService.EnsureRegistered();

            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string logDir = Path.Combine(localAppData, "AegisPC", "Logs");
            try { Directory.CreateDirectory(logDir); } catch { }
            string logPath = Path.Combine(logDir, "aegis_startup.log");

            try
            {
                try { File.WriteAllText(logPath, $"[INFO {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] Ultron Defender Main started. Args: {string.Join(" ", args)}\n"); } catch { }

                var app = new App();
                app.InitializeComponent();
                app.Run();
            }
            catch (Exception ex)
            {
                string errorMsg = $"CRITICAL STARTUP ERROR:\nType: {ex.GetType().FullName}\nMessage: {ex.Message}\nStackTrace:\n{ex.StackTrace}\n";
                if (ex.InnerException != null)
                {
                    errorMsg += $"\nInnerException: {ex.InnerException.GetType().FullName}\nInnerMessage: {ex.InnerException.Message}\n";
                }
                try { File.AppendAllText(logPath, errorMsg); } catch { }
                MessageBox.Show(errorMsg, "Ultron Defender - Başlatma Hatası", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _running = false;
                if (_mutex != null)
                {
                    try { _mutex.ReleaseMutex(); } catch { }
                    _mutex.Dispose();
                }
                if (_activateEvent != null)
                {
                    try { _activateEvent.Set(); } catch { }
                    _activateEvent.Dispose();
                }
            }
        }

        private static string? ParseScanArgument(string[] args)
        {
            if (args == null || args.Length == 0) return null;

            for (int i = 0; i < args.Length; i++)
            {
                var a = args[i].Trim();
                if (a.Equals("/scan", StringComparison.OrdinalIgnoreCase) || 
                    a.Equals("-scan", StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 < args.Length)
                    {
                        return args[i + 1].Trim('\"');
                    }
                }
                else if (File.Exists(a) || Directory.Exists(a))
                {
                    return a.Trim('\"');
                }
            }
            return null;
        }

        private static void SignalRunningInstance(string? targetScanPath = null)
        {
            string payload = !string.IsNullOrWhiteSpace(targetScanPath) ? "SCAN:" + targetScanPath : "ACTIVATE";

            // 1. Önce Named Pipe ile doğrudan sinyal yolla
            try
            {
                using var pipeClient = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
                pipeClient.Connect(1000);
                using var writer = new StreamWriter(pipeClient) { AutoFlush = true };
                writer.WriteLine(payload);
                return;
            }
            catch { }

            // 2. Named Pipe yanıt vermezse EventWaitHandle ile sinyal yolla
            try
            {
                if (EventWaitHandle.TryOpenExisting(EventName, out var existingEvent))
                {
                    existingEvent.Set();
                    existingEvent.Dispose();
                }
            }
            catch { }
        }

        private static void StartActivationListeners()
        {
            // Named Pipe Dinleyici
            _pipeThread = new Thread(() =>
            {
                while (_running)
                {
                    try
                    {
                        using var server = new NamedPipeServerStream(PipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte);
                        server.WaitForConnection();
                        using var reader = new StreamReader(server);
                        var msg = reader.ReadLine();
                        if (!string.IsNullOrEmpty(msg))
                        {
                            if (msg.StartsWith("SCAN:", StringComparison.OrdinalIgnoreCase))
                            {
                                string scanPath = msg.Substring(5).Trim();
                                TriggerWindowActivationAndScan(scanPath);
                            }
                            else if (msg == "ACTIVATE")
                            {
                                TriggerWindowActivation();
                            }
                        }
                    }
                    catch
                    {
                        if (!_running) break;
                        Thread.Sleep(200);
                    }
                }
            })
            {
                IsBackground = true,
                Name = "Ultron_NamedPipe_Listener"
            };
            _pipeThread.Start();

            // EventWaitHandle Dinleyici (İkincil yedek)
            try
            {
                _activateEvent = new EventWaitHandle(false, EventResetMode.AutoReset, EventName);
                _listenerThread = new Thread(() =>
                {
                    while (_running)
                    {
                        try
                        {
                            if (_activateEvent.WaitOne(1000))
                            {
                                if (!_running) break;
                                TriggerWindowActivation();
                            }
                        }
                        catch { }
                    }
                })
                {
                    IsBackground = true,
                    Name = "Ultron_Event_Listener"
                };
                _listenerThread.Start();
            }
            catch { }
        }

        private static void TriggerWindowActivation()
        {
            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                try
                {
                    if (MainWindow.Instance != null)
                    {
                        MainWindow.Instance.ShowAndActivate();
                    }
                    else if (Application.Current?.MainWindow is MainWindow mw)
                    {
                        mw.ShowAndActivate();
                    }
                }
                catch { }
            }));
        }

        private static void TriggerWindowActivationAndScan(string targetPath)
        {
            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                try
                {
                    if (MainWindow.Instance != null)
                    {
                        MainWindow.Instance.NavigateToScanAndScanPath(targetPath);
                    }
                    else if (Application.Current?.MainWindow is MainWindow mw)
                    {
                        mw.NavigateToScanAndScanPath(targetPath);
                    }
                }
                catch { }
            }));
        }
    }
}
