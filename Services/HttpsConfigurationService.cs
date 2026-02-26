using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace Reversify.Services
{
    /// <summary>
    /// Service to manage HTTPS certificates per host
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
        /// Register a certificate for a specific host using a directory
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
                Log.Warn($"Could not load certificate for {host}");
            }
        }

        /// <summary>
        /// Register a certificate for a specific host (legacy method for compatibility)
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
                Log.Warn($"Could not load certificate for {host}");
            }
        }

        private void RegisterCertificateForHostAndAliases(string host, X509Certificate2 cert)
        {
            var normalized = host.Split(':')[0].ToLowerInvariant();
            _certificates.AddOrUpdate(normalized, cert, (key, old) => cert);
            Log.Info($"Certificate registered for {normalized}");

            // Register www/non-www alias if the certificate covers it
            var alt = normalized.StartsWith("www.") ? normalized.Substring(4) : $"www.{normalized}";
            if (CertificateLoader.MatchesHost(cert, alt))
            {
                _certificates.AddOrUpdate(alt, cert, (key, old) => cert);
                Log.Info($"Certificate also registered for alias: {alt}");
            }
        }

        /// <summary>
        /// Remove certificate for a host (and its alias if present)
        /// </summary>
        public void RemoveCertificate(string host)
        {
            var normalized = host.Split(':')[0].ToLowerInvariant();
            if (_certificates.TryRemove(normalized, out var cert))
            {
                cert.Dispose();
                Log.Info($"Certificate removed for {normalized}");
            }

            var alt = normalized.StartsWith("www.") ? normalized.Substring(4) : $"www.{normalized}";
            if (_certificates.TryRemove(alt, out var altCert))
            {
                altCert.Dispose();
                Log.Info($"Certificate removed for alias: {alt}");
            }
        }

        /// <summary>
        /// Get certificate for a specific host
        /// </summary>
        public X509Certificate2? GetCertificateForHost(string host)
        {
            // Normalize host
            var hostWithoutPort = host.Split(':')[0].ToLowerInvariant();

            // Direct lookup and validate against CN/SAN
            if (_certificates.TryGetValue(hostWithoutPort, out var cert))
            {
                if (CertificateLoader.MatchesHost(cert, hostWithoutPort))
                {
                    return cert;
                }
                Log.Warn($"Certificate found does not match requested host: {hostWithoutPort} -> {cert.Subject}");
            }

            // Try with/without www
            if (hostWithoutPort.StartsWith("www."))
            {
                var withoutWww = hostWithoutPort.Substring(4);
                if (_certificates.TryGetValue(withoutWww, out cert) && CertificateLoader.MatchesHost(cert, hostWithoutPort))
                {
                    Log.Info($"Certificate resolved by alias: {hostWithoutPort} -> {withoutWww}");
                    return cert;
                }
            }
            else
            {
                var withWww = $"www.{hostWithoutPort}";
                if (_certificates.TryGetValue(withWww, out cert) && CertificateLoader.MatchesHost(cert, hostWithoutPort))
                {
                    Log.Info($"Certificate resolved by alias: {hostWithoutPort} -> {withWww}");
                    return cert;
                }
            }

            Log.Warn($"No valid certificate (CN/SAN) for host: {hostWithoutPort}");
            return null;
        }

        /// <summary>
        /// Get all configured hosts with certificates
        /// </summary>
        public IEnumerable<string> GetConfiguredHosts()
        {
            return _certificates.Keys;
        }
    }
}
