using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services
{
    /// <summary>
    /// Otomatik karantinalar için 30 günlük geri alma günlüğü ("cofa") ve karar zinciri görünümü sunan servis arayüzü.
    /// </summary>
    public interface IQuarantineUndoLogService
    {
        Task RecordQuarantineDecisionAsync(
            int quarantineId,
            string originalPath,
            int riskScore,
            string threatName,
            string decisionChain,
            CancellationToken ct = default);

        Task<List<QuarantineUndoEntry>> GetUndoLogEntriesAsync(
            TimeSpan? retentionWindow = null,
            CancellationToken ct = default);

        Task<string?> GetDecisionChainAsync(
            int quarantineId,
            CancellationToken ct = default);

        Task<int> BulkRestoreAsync(
            IEnumerable<int> quarantineIds,
            CancellationToken ct = default);
    }
}
