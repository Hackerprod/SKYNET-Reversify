using System.Collections.Concurrent;
using Reversify.Models;

namespace Reversify.Modules
{
    /// <summary>
    /// DDoS attack detection module based on per-IP traffic analysis
    /// </summary>
    public class DDoSDetectionModule : IAttackDetectionModule
    {
        private readonly ConcurrentDictionary<string, IpTrafficStats> _ipStats;
        private readonly IConfiguration _configuration;

        // Default configuration
        private int _maxRequestsPerMinute = 100;
        private int _maxRequestsPerSecond = 10;
        private TimeSpan _timeWindow = TimeSpan.FromMinutes(5);
        private int _blockDurationMinutes = 30;

        private readonly ConcurrentDictionary<string, DateTime> _blockedIps;

        public string ModuleName => "DDoS Detection";

        public DDoSDetectionModule(
            IConfiguration configuration)
        {
            _configuration = configuration;
            _ipStats = new ConcurrentDictionary<string, IpTrafficStats>();
            _blockedIps = new ConcurrentDictionary<string, DateTime>();

            LoadConfiguration();
            StartCleanupTask();
        }

        private void LoadConfiguration()
        {
            _maxRequestsPerMinute = _configuration.GetValue("DDoS:MaxRequestsPerMinute", 100);
            _maxRequestsPerSecond = _configuration.GetValue("DDoS:MaxRequestsPerSecond", 10);
            _timeWindow = TimeSpan.FromMinutes(_configuration.GetValue("DDoS:TimeWindowMinutes", 5));
            _blockDurationMinutes = _configuration.GetValue("DDoS:BlockDurationMinutes", 30);
        }

        public async Task<AttackDetectionResult?> DetectAsync(HttpContext context)
        {
            var ipAddress = GetClientIpAddress(context);
            if (string.IsNullOrEmpty(ipAddress))
                return null;

            // Check if the IP is blocked
            if (_blockedIps.TryGetValue(ipAddress, out var blockedUntil))
            {
                if (DateTime.UtcNow < blockedUntil)
                {
                    return new AttackDetectionResult
                    {
                        IsAttack = true,
                        AttackType = "DDoS - IP Bloqueada",
                        IpAddress = ipAddress,
                        Reason = $"IP bloqueada hasta {blockedUntil:yyyy-MM-dd HH:mm:ss} UTC",
                        Severity = 10
                    };
                }
                else
                {
                    // Unblock IP
                    _blockedIps.TryRemove(ipAddress, out _);
                    Log.Info($"IP unblocked: {ipAddress}");
                }
            }

            // Get or create stats for this IP
            var stats = _ipStats.GetOrAdd(ipAddress, _ => new IpTrafficStats
            {
                IpAddress = ipAddress,
                FirstRequest = DateTime.UtcNow,
                LastRequest = DateTime.UtcNow,
                RequestCount = 0,
                RequestTimestamps = new List<DateTime>()
            });

            // Update stats
            var now = DateTime.UtcNow;
            stats.LastRequest = now;
            stats.RequestCount++;
            stats.RequestTimestamps.Add(now);

            // Remove old timestamps (outside time window)
            stats.RequestTimestamps.RemoveAll(t => now - t > _timeWindow);

            // DDoS detection

            // 1. Too many requests per second
            var requestsInLastSecond = stats.RequestTimestamps.Count(t => now - t < TimeSpan.FromSeconds(1));
            if (requestsInLastSecond > _maxRequestsPerSecond)
            {
                BlockIp(ipAddress);
                return new AttackDetectionResult
                {
                    IsAttack = true,
                    AttackType = "DDoS - Burst Attack",
                    IpAddress = ipAddress,
                    Reason = $"Demasiadas solicitudes por segundo: {requestsInLastSecond}",
                    Severity = 9
                };
            }

            // 2. Too many requests per minute
            var requestsInLastMinute = stats.RequestTimestamps.Count(t => now - t < TimeSpan.FromMinutes(1));
            if (requestsInLastMinute > _maxRequestsPerMinute)
            {
                BlockIp(ipAddress);
                return new AttackDetectionResult
                {
                    IsAttack = true,
                    AttackType = "DDoS - Sustained Attack",
                    IpAddress = ipAddress,
                    Reason = $"Demasiadas solicitudes por minuto: {requestsInLastMinute}",
                    Severity = 8
                };
            }

            return null;
        }

        private void BlockIp(string ipAddress)
        {
            var blockUntil = DateTime.UtcNow.AddMinutes(_blockDurationMinutes);
            _blockedIps.AddOrUpdate(ipAddress, blockUntil, (key, old) => blockUntil);
            Log.Warn($"IP blocked due to suspected DDoS: {ipAddress} until {blockUntil:yyyy-MM-dd HH:mm:ss} UTC");
        }

        private string GetClientIpAddress(HttpContext context)
        {
            // Try to get the real client IP (consider proxies)
            var ipAddress = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(ipAddress))
            {
                // X-Forwarded-For can contain multiple IPs, take the first
                return ipAddress.Split(',')[0].Trim();
            }

            return context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        }

        public void Reset()
        {
            _ipStats.Clear();
            _blockedIps.Clear();
            Log.Info("DDoS stats reset");
        }

        private void StartCleanupTask()
        {
            // Background task to clean old stats
            Task.Run(async () =>
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromMinutes(5));

                    var now = DateTime.UtcNow;
                    var oldIps = _ipStats.Where(kvp => now - kvp.Value.LastRequest > _timeWindow)
                                        .Select(kvp => kvp.Key)
                                        .ToList();

                    foreach (var ip in oldIps)
                    {
                        _ipStats.TryRemove(ip, out _);
                    }

                    if (oldIps.Count > 0)
                    {
                        Log.Info($"Cleaned {oldIps.Count} inactive IPs from stats");
                    }
                }
            });
        }
    }
}
