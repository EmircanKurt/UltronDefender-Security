using System;

namespace AegisPC.Core.Models
{
    public class ParentalRule
    {
        public int Id { get; set; }
        public required string RuleName { get; set; }
        public required string RuleType { get; set; }
        public string? Target { get; set; }
        public int? DailyLimitMinutes { get; set; }
        public bool IsEnabled { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}
