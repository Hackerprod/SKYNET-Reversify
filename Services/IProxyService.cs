using Reversify.Models;

namespace Reversify.Services
{
    /// <summary>
    /// Interface for the reverse proxy service
    /// </summary>
    public interface IProxyService
    {
        void AddOrUpdateProxy(ProxyConfig config);
        void RemoveProxy(string dnsUrl);
        ProxyConfig? GetProxyByHost(string host);
        IEnumerable<ProxyConfig> GetAllProxies();
    }
}
