using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests
{
    public class CriticalEventQueueFloodTests : IDisposable
    {
        private readonly string _testDir;

        public CriticalEventQueueFloodTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "Aegis_FloodTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testDir))
                {
                    Directory.Delete(_testDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task RealTimeEventIngestor_SaturatedTelemetryQueue_NeverDropsCriticalSecurityEvent()
        {
            // Small telemetry capacity to saturate quickly
            int telemetryCapacity = 100;
            using var ingestor = new RealTimeEventIngestor(channelCapacity: telemetryCapacity);

            var processedCriticalEvents = new ConcurrentBag<NormalizedFileEvent>();
            var processedTelemetryEvents = new ConcurrentBag<NormalizedFileEvent>();

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            // Start workers to consume events
            ingestor.StartWorkers(workerCount: 2, async (fileEvent, token) =>
            {
                if (fileEvent.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    processedCriticalEvents.Add(fileEvent);
                }
                else
                {
                    processedTelemetryEvents.Add(fileEvent);
                }
                await Task.Yield();
            }, cts.Token);

            // 1. Flood with 4,999 telemetry (.txt) events without pacing
            for (int i = 0; i < 4999; i++)
            {
                ingestor.EnqueueEvent(RealTimeEventType.Created, Path.Combine(_testDir, $"telemetry_noise_{i}.txt"));
            }

            // 2. Enqueue exactly 1 critical security event (.exe)
            string criticalPayloadPath = Path.Combine(_testDir, "eicar_dropper.exe");
            ingestor.EnqueueEvent(RealTimeEventType.Created, criticalPayloadPath);

            // Wait until critical event is processed
            var startWait = DateTime.UtcNow;
            while (processedCriticalEvents.IsEmpty && (DateTime.UtcNow - startWait).TotalSeconds < 5)
            {
                await Task.Delay(20);
            }

            // Verify: Critical event was NEVER dropped, despite massive telemetry flood
            Assert.False(processedCriticalEvents.IsEmpty, "Critical security event must NOT be dropped under queue pressure!");
            Assert.Contains(processedCriticalEvents, e => e.FilePath.Equals(criticalPayloadPath, StringComparison.OrdinalIgnoreCase));

            // Telemetry queue should have dropped excess items
            Assert.True(ingestor.TotalDroppedEvents > 0, "Telemetry queue should record dropped telemetry noise under saturation.");

            ingestor.Stop();
        }
    }
}
