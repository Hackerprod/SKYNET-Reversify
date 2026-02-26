using System.Collections.Concurrent;
using Reversify.Models;

namespace Reversify.Services
{
    /// <summary>
    /// Simplified reverse proxy service
    /// </summary>
    public class ProxyService : IProxyService
    {
        private readonly ConcurrentDictionary<string, ProxyConfig> _proxies;

        public ProxyService()
        {
            _proxies = new ConcurrentDictionary<string, ProxyConfig>(StringComparer.OrdinalIgnoreCase);
        }

        public void AddOrUpdateProxy(ProxyConfig config)
        {
            _proxies.AddOrUpdate(config.DnsUrl, config, (key, old) => config);
            Log.Info($"Proxy added/updated: {config.DnsUrl} -> {config.LocalUrl}");
        }

        public void RemoveProxy(string dnsUrl)
        {
            if (_proxies.TryRemove(dnsUrl, out var config))
            {
                Log.Info($"Proxy removed: {dnsUrl}");
            }
        }

        public ProxyConfig? GetProxyByHost(string host)
        {
            // Normalize host (remove port if present)
            var hostWithoutPort = host.Split(':')[0].ToLowerInvariant();

            // Try direct match
            if (_proxies.TryGetValue(hostWithoutPort, out var config))
            {
                return config;
            }

            // Try with www. if missing
            if (!hostWithoutPort.StartsWith("www."))
            {
                var withWww = $"www.{hostWithoutPort}";
                if (_proxies.TryGetValue(withWww, out config))
                {
                    return config;
                }
            }

            // Try without www. if present
            if (hostWithoutPort.StartsWith("www."))
            {
                var withoutWww = hostWithoutPort.Substring(4);
                if (_proxies.TryGetValue(withoutWww, out config))
                {
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
