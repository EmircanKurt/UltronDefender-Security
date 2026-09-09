using System;
using System.Threading;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Concrete implementation of <see cref="IScanSession"/> managing a scan run's lifecycle.
    /// </summary>
    public class ScanSession : IScanSession
    {
        private readonly CancellationTokenSource _cts;
        private readonly Action _onPause;
        private readonly Action _onResume;
        private readonly Action _onCancel;

        public Guid SessionId { get; }
        public ScanType ScanType { get; }
        public string CustomPath { get; }
        public DateTime StartedAtUtc { get; }
        public bool IsActive { get; internal set; }
        public bool IsPaused { get; internal set; }
        public ScanProgress? LatestProgress { get; internal set; }
        public CancellationToken CancellationToken => _cts.Token;

        public ScanSession(
            ScanType scanType,
            string customPath,
            CancellationTokenSource cts,
            Action onPause,
            Action onResume,
            Action onCancel)
        {
            SessionId = Guid.NewGuid();
            ScanType = scanType;
            CustomPath = customPath ?? string.Empty;
            StartedAtUtc = DateTime.UtcNow;
            IsActive = true;
            IsPaused = false;
            _cts = cts;
            _onPause = onPause;
            _onResume = onResume;
            _onCancel = onCancel;
        }

        public void Pause()
        {
            if (!IsActive || IsPaused) return;
            IsPaused = true;
            _onPause?.Invoke();
        }

        public void Resume()
        {
            if (!IsActive || !IsPaused) return;
            IsPaused = false;
            _onResume?.Invoke();
        }

        public void Cancel()
        {
            if (!IsActive) return;
            try
            {
                _cts.Cancel();
            }
            catch (ObjectDisposedException) { }
            _onCancel?.Invoke();
        }

        public void MarkEnded()
        {
            IsActive = false;
            IsPaused = false;
        }
    }
}
