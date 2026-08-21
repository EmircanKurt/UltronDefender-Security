using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.RealTime
{
    public class RealTimeFileMonitor : IDisposable
    {
        private readonly ILogger<RealTimeFileMonitor> _logger;
        private readonly FileSystemWatcher _watcher;
        private readonly ConcurrentQueue<string> _fileQueue = new();

        public RealTimeFileMonitor(ILogger<RealTimeFileMonitor> logger)
        {
            _logger = logger;
            _watcher = new FileSystemWatcher(@"C:\")
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                IncludeSubdirectories = true
            };
            
            _watcher.Created += OnFileEvent;
            _watcher.Changed += OnFileEvent;
        }

        private void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            _fileQueue.Enqueue(e.FullPath);
        }

        public void Start() => _watcher.EnableRaisingEvents = true;
        public void Stop() => _watcher.EnableRaisingEvents = false;
        
        public void Dispose()
        {
            _watcher?.Dispose();
        }
    }
}
