using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace Reversify.Services
{
    /// <summary>
    /// Servicio para gestionar certificados HTTPS por host
    /// </summary>
    public class HttpsConfigurationService
    {
        private readonly ConcurrentDictionary<string, X509Certificate2> _certificates;
        private readonly ILogger<HttpsConfigurationService> _logger;

        public HttpsConfigurationService(ILogger<HttpsConfigurationService> logger)
        {
            _logger = logger;
            _certificates = new ConcurrentDictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Registra un certificado para un host específico usando un directorio
        /// </summary>
        public void AddOrUpdateCertificateFromDirectory(string host, string? directory, string? password = null)
        {
            if (string.IsNullOrEmpty(directory))
            {
                RemoveCertificate(host);
                return;
            }

            var cert = CertificateLoader.LoadCertificateFromDirectory(directory, host, password, _logger);

            if (cert != null && CertificateLoader.IsCertificateValid(cert, _logger))
            {
                RegisterCertificateForHostAndAliases(host, cert);
            }
            else
            {
                _logger.LogWarning($"No se pudo cargar certificado para {host}");
            }
        }

        /// <summary>
        /// Registra un certificado para un host específico (método legacy para compatibilidad)
        /// </summary>
        public void AddOrUpdateCertificate(string host, string? certPath, string? keyPath = null, string? password = null)
        {
            if (string.IsNullOrEmpty(certPath))
            {
                RemoveCertificate(host);
                return;
            }

            var cert = CertificateLoader.LoadCertificate(certPath, keyPath, password, _logger);

            if (cert != null && CertificateLoader.IsCertificateValid(cert, _logger))
            {
                RegisterCertificateForHostAndAliases(host, cert);
            }
            else
            {
                _logger.LogWarning($"No se pudo cargar certificado para {host}");
            }
        }

        private void RegisterCertificateForHostAndAliases(string host, X509Certificate2 cert)
        {
            var normalized = host.Split(':')[0].ToLowerInvariant();
            _certificates.AddOrUpdate(normalized, cert, (key, old) => cert);
            _logger.LogInformation($"Certificado registrado para {normalized}");

            // Registrar alias www/sin-www si el certificado lo cubre
            var alt = normalized.StartsWith("www.") ? normalized.Substring(4) : $"www.{normalized}";
            if (CertificateLoader.MatchesHost(cert, alt))
            {
                _certificates.AddOrUpdate(alt, cert, (key, old) => cert);
                _logger.LogInformation($"Certificado también registrado para alias: {alt}");
            }
        }

        /// <summary>
        /// Remueve el certificado de un host (y su alias si existiera)
        /// </summary>
        public void RemoveCertificate(string host)
        {
            var normalized = host.Split(':')[0].ToLowerInvariant();
            if (_certificates.TryRemove(normalized, out var cert))
            {
                cert.Dispose();
                _logger.LogInformation($"Certificado removido para {normalized}");
            }

            var alt = normalized.StartsWith("www.") ? normalized.Substring(4) : $"www.{normalized}";
            if (_certificates.TryRemove(alt, out var altCert))
            {
                altCert.Dispose();
                _logger.LogInformation($"Certificado removido para alias: {alt}");
            }
        }

        /// <summary>
        /// Obtiene el certificado para un host específico
        /// </summary>
        public X509Certificate2? GetCertificateForHost(string host)
        {
            // Normalizar el host
            var hostWithoutPort = host.Split(':')[0].ToLowerInvariant();

            // Buscar certificado directo y validar contra CN/SAN
            if (_certificates.TryGetValue(hostWithoutPort, out var cert))
            {
                if (CertificateLoader.MatchesHost(cert, hostWithoutPort))
                {
                    return cert;
                }
                _logger.LogWarning($"Certificado encontrado no coincide con host solicitado: {hostWithoutPort} -> {cert.Subject}");
            }

            // Buscar con/sin www
            if (hostWithoutPort.StartsWith("www."))
            {
                var withoutWww = hostWithoutPort.Substring(4);
                if (_certificates.TryGetValue(withoutWww, out cert) && CertificateLoader.MatchesHost(cert, hostWithoutPort))
                {
                    _logger.LogDebug($"Certificado resuelto por alias: {hostWithoutPort} -> {withoutWww}");
                    return cert;
                }
            }
            else
            {
                var withWww = $"www.{hostWithoutPort}";
                if (_certificates.TryGetValue(withWww, out cert) && CertificateLoader.MatchesHost(cert, hostWithoutPort))
                {
                    _logger.LogDebug($"Certificado resuelto por alias: {hostWithoutPort} -> {withWww}");
                    return cert;
                }
            }

            _logger.LogWarning($"No hay certificado válido (CN/SAN) para host: {hostWithoutPort}");
            return null;
        }

        /// <summary>
        /// Obtiene todos los hosts con certificados configurados
        /// </summary>
        public IEnumerable<string> GetConfiguredHosts()
        {
            return _certificates.Keys;
        }
    }
}
