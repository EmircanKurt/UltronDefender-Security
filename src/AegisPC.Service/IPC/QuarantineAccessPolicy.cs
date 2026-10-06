using System;
using AegisPC.Core.Models;

namespace AegisPC.Service.IPC;

/// <summary>Owner isolation for service records. Legacy records without owner evidence are administrative only.</summary>
public static class QuarantineAccessPolicy
{
    /// <summary>Accepts only an independently authenticated SID, never an owner claimed in the request payload.</summary>
    public static bool CanAccess(QuarantineEntry entry, string authenticatedSid, bool administrator) =>
        administrator || (!string.IsNullOrEmpty(authenticatedSid) && !string.IsNullOrEmpty(entry.OwnerSid) &&
            string.Equals(entry.OwnerSid, authenticatedSid, StringComparison.OrdinalIgnoreCase));
}
