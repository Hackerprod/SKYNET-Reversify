using ProxInv.Models;

namespace ProxInv.Services
{
    /// <summary>
    /// Interfaz para el servicio de proxy inverso
    /// </summary>
    public interface IProxyService
    {
        void AddOrUpdateProxy(ProxyConfig config);
        void RemoveProxy(string dnsUrl);
        ProxyConfig? GetProxyByHost(string host);
        IEnumerable<ProxyConfig> GetAllProxies();
    }
}
