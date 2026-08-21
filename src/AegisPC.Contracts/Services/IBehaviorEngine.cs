using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services
{
    public interface IBehaviorEngine
    {
        event Action<SecurityIncident>? OnIncidentCreated;
        event Action<string, string>? OnThreatContained;

        Task ProcessEventAsync(BehaviorEvent behaviorEvent, CancellationToken cancellationToken = default);
        Task<List<SecurityIncident>> GetActiveIncidentsAsync(CancellationToken cancellationToken = default);
        Task<SecurityIncident?> GetIncidentByIdAsync(string incidentId, CancellationToken cancellationToken = default);
        Task<bool> RemediateIncidentAsync(string incidentId, CancellationToken cancellationToken = default);
    }
}
