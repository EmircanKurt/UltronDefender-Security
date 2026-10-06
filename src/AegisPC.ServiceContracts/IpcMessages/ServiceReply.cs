using System;
using System.Collections.Generic;
using AegisPC.Core.Models;

namespace AegisPC.ServiceContracts.IpcMessages;

/// <summary>One correlated operation result; success means the action completed, not merely that it was queued.</summary>
public sealed class ServiceReply
{
    /// <summary>Non-empty request identity supplied by the client.</summary>
    public Guid RequestId { get; set; }
    /// <summary>Whether the operation was acknowledged as successful.</summary>
    public bool Success { get; set; }
    /// <summary>Path-free failure or success code.</summary>
    public string Code { get; set; } = string.Empty;
    /// <summary>Typed, authorized result serialized as JSON, bounded by the pipe protocol.</summary>
    public string? Payload { get; set; }
}

/// <summary>Quarantine request data. Owner and risk claims are never accepted from the client.</summary>
public sealed class AuthorizedVaultRequest
{
    /// <summary>Existing entry identity for read, restore or delete.</summary>
    public int Id { get; set; }
    /// <summary>Candidate path, re-inspected by the service before any quarantine action.</summary>
    public string? Path { get; set; }
    /// <summary>Ascending pagination cursor, not an authorization grant.</summary>
    public int AfterId { get; set; }
    /// <summary>Optional restore target; restricted to administrative requests.</summary>
    public string? Destination { get; set; }
}

/// <summary>Bounded page of records already filtered by the service for the authenticated caller.</summary>
public sealed class QuarantinePage
{
    /// <summary>At most 32 authorized records.</summary>
    public List<QuarantineEntry> Entries { get; set; } = new();
    /// <summary>Next cursor when more authorized records exist, otherwise null.</summary>
    public int? NextAfterId { get; set; }
}
