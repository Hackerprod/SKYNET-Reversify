namespace Reversify.Models
{
    /// <summary>
    /// Attack detection result
    /// </summary>
    public class AttackDetectionResult
    {
        public bool IsAttack { get; set; }
        public string AttackType { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
        public string Reason { get; set; } = string.Empty;
        public int Severity { get; set; } // 1-10
    }

    /// <summary>
    /// Traffic stats per IP
    /// </summary>
    public class IpTrafficStats
    {
        public string IpAddress { get; set; } = string.Empty;
        public int RequestCount { get; set; }
        public DateTime FirstRequest { get; set; }
        public DateTime LastRequest { get; set; }
        public List<DateTime> RequestTimestamps { get; set; } = new();
    }
}
