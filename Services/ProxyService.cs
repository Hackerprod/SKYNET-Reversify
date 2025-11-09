using System.Collections.Concurrent;
using ProxInv.Models;

namespace ProxInv.Services
{
    /// <summary>
    /// Servicio de proxy inverso simplificado
    /// </summary>
    public class ProxyService : IProxyService
    {
        private readonly ConcurrentDictionary<string, ProxyConfig> _proxies;
        private readonly ILogger<ProxyService> _logger;

        public ProxyService(ILogger<ProxyService> logger)
        {
            _logger = logger;
            _proxies = new ConcurrentDictionary<string, ProxyConfig>(StringComparer.OrdinalIgnoreCase);
        }

        public void AddOrUpdateProxy(ProxyConfig config)
        {
            _proxies.AddOrUpdate(config.DnsUrl, config, (key, old) => config);
            _logger.LogInformation($"✅ Proxy agregado/actualizado: {config.DnsUrl} -> {config.LocalUrl}");
        }

        public void RemoveProxy(string dnsUrl)
        {
            if (_proxies.TryRemove(dnsUrl, out var config))
            {
                _logger.LogInformation($"🗑️  Proxy removido: {dnsUrl}");
            }
        }

        public ProxyConfig? GetProxyByHost(string host)
        {
            // Normalizar el host (remover puerto si existe)
            var hostWithoutPort = host.Split(':')[0].ToLowerInvariant();

            // Intentar match directo
            if (_proxies.TryGetValue(hostWithoutPort, out var config))
            {
                return config;
            }

            // Intentar con www. si no lo tiene
            if (!hostWithoutPort.StartsWith("www."))
            {
                var withWww = $"www.{hostWithoutPort}";
                if (_proxies.TryGetValue(withWww, out config))
                {
                    _logger.LogDebug($"Match encontrado con www: {hostWithoutPort} -> {withWww}");
                    return config;
                }
            }

            // Intentar sin www. si lo tiene
            if (hostWithoutPort.StartsWith("www."))
            {
                var withoutWww = hostWithoutPort.Substring(4);
                if (_proxies.TryGetValue(withoutWww, out config))
                {
                    _logger.LogDebug($"Match encontrado sin www: {hostWithoutPort} -> {withoutWww}");
                    return config;
                }
            }

            return null;
        }

        public IEnumerable<ProxyConfig> GetAllProxies()
        {
            return _proxies.Values;
        }
    }
}
