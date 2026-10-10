namespace AegisPC.Core.Enums;
/// <summary>Separates durable action intent from its later observed success, failure or denial.</summary>
public enum AuditResult { Success = 0, Failed = 1, Denied = 2, Cancelled = 3, Pending = 4 }
