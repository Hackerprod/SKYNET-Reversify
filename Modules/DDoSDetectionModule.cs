using System.Collections.Concurrent;
using Reversify.Models;

namespace Reversify.Modules
{
    /// <summary>
    /// Módulo de detección de ataques DDoS basado en análisis de tráfico por IP
    /// </summary>
    public class DDoSDetectionModule : IAttackDetectionModule
    {
        private readonly ConcurrentDictionary<string, IpTrafficStats> _ipStats;
        private readonly ILogger<DDoSDetectionModule> _logger;
        private readonly IConfiguration _configuration;

        // Configuración por defecto
        private int _maxRequestsPerMinute = 100;
        private int _maxRequestsPerSecond = 10;
        private TimeSpan _timeWindow = TimeSpan.FromMinutes(5);
        private int _blockDurationMinutes = 30;

        private readonly ConcurrentDictionary<string, DateTime> _blockedIps;

        public string ModuleName => "DDoS Detection";

        public DDoSDetectionModule(
            ILogger<DDoSDetectionModule> logger,
            IConfiguration configuration)
        {
            _logger = logger;
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

            // Verificar si la IP está bloqueada
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
                    // Desbloquear IP
                    _blockedIps.TryRemove(ipAddress, out _);
                    _logger.LogInformation($"IP desbloqueada: {ipAddress}");
                }
            }

            // Obtener o crear estadísticas para esta IP
            var stats = _ipStats.GetOrAdd(ipAddress, _ => new IpTrafficStats
            {
                IpAddress = ipAddress,
                FirstRequest = DateTime.UtcNow,
                LastRequest = DateTime.UtcNow,
                RequestCount = 0,
                RequestTimestamps = new List<DateTime>()
            });

            // Actualizar estadísticas
            var now = DateTime.UtcNow;
            stats.LastRequest = now;
            stats.RequestCount++;
            stats.RequestTimestamps.Add(now);

            // Limpiar timestamps antiguos (fuera de la ventana de tiempo)
            stats.RequestTimestamps.RemoveAll(t => now - t > _timeWindow);

            // Detección de DDoS

            // 1. Demasiadas solicitudes por segundo
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

            // 2. Demasiadas solicitudes por minuto
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
            _logger.LogWarning($"IP bloqueada por sospecha de DDoS: {ipAddress} hasta {blockUntil:yyyy-MM-dd HH:mm:ss} UTC");
        }

        private string GetClientIpAddress(HttpContext context)
        {
            // Intentar obtener la IP real del cliente (considerando proxies)
            var ipAddress = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(ipAddress))
            {
                // X-Forwarded-For puede contener múltiples IPs, tomar la primera
                return ipAddress.Split(',')[0].Trim();
            }

            return context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        }

        public void Reset()
        {
            _ipStats.Clear();
            _blockedIps.Clear();
            _logger.LogInformation("Estadísticas de DDoS reiniciadas");
        }

        private void StartCleanupTask()
        {
            // Tarea en segundo plano para limpiar estadísticas antiguas
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
                        _logger.LogInformation($"Limpiadas {oldIps.Count} IPs inactivas de las estadísticas");
                    }
                }
            });
        }
    }
}
