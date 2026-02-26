using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Reversify.Services
{
    /// <summary>
    /// Service to load SSL certificates in different formats
    /// </summary>
    public static class CertificateLoader
    {
        /// <summary>
        /// Check whether the certificate matches the requested host (CN or SANs)
        /// </summary>
        public static bool MatchesHost(X509Certificate2 cert, string host)
        {
            if (string.IsNullOrEmpty(host)) return false;

            try
            {
                var target = host.Split(':')[0].Trim().ToLowerInvariant();

                // 1) Check Subject Alternative Name (SAN) DNS entries (OID 2.5.29.17)
                foreach (var ext in cert.Extensions)
                {
                    if (ext.Oid?.Value == "2.5.29.17")
                    {
                        // AsnEncodedData.Format(true) returns DNS entries as text
                        var formatted = ext.Format(true);
                        // Look for lines like: DNS Name=example.com
                        var lines = formatted.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var line in lines)
                        {
                            var idx = line.IndexOf('=');
                            if (idx > 0)
                            {
                                var key = line.Substring(0, idx).Trim().ToLowerInvariant();
                                var value = line.Substring(idx + 1).Trim().ToLowerInvariant();
                                if (key.Contains("dns") && HostMatches(value, target))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }

                // 2) Fallback: CN from Subject
                var subject = cert.GetNameInfo(X509NameType.DnsName, false);
                if (!string.IsNullOrEmpty(subject) && HostMatches(subject.ToLowerInvariant(), target))
                {
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool HostMatches(string pattern, string host)
        {
            if (string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase))
                return true;

            // Support wildcards like *.domain.com
            if (pattern.StartsWith("*.", StringComparison.Ordinal) && host.Length > 2)
            {
                var suffix = pattern.Substring(1); // ".domain.com"
                return host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) && host.Count(c => c == '.') >= 2;
            }

            return false;
        }

        /// <summary>
        /// Load a certificate from a directory by searching common extensions
        /// Looks for any .crt + .key, .pfx or .p12 in the directory
        /// </summary>
        public static X509Certificate2? LoadCertificateFromDirectory(
            string? directory,
            string host,
            string? password = null,
            ILogger? logger = null)
        {
            if (string.IsNullOrEmpty(directory))
                return null;

            if (!Directory.Exists(directory))
            {
                Log.Warn($"Certificate directory does not exist: {directory}");
                return null;
            }

            Log.Info($"Searching certificates in: {directory}");

            // Normalize host (no port)
            var hostWithoutPort = host.Split(':')[0].ToLowerInvariant();

            // 1. Try exact host name first
            var cert = TryLoadExactMatch(directory, hostWithoutPort, password, logger);
            if (cert != null)
                return cert;

            // 1.5 If no {host}.pfx but there is a single .crt and some .key, generate a .pfx dynamically
            try
            {
                var candidateCrt = Directory.GetFiles(directory, "*.crt", SearchOption.TopDirectoryOnly);
                var candidateKeys = Directory.GetFiles(directory, "*.key", SearchOption.TopDirectoryOnly);
                if (candidateCrt.Length == 1 && candidateKeys.Length >= 1)
                {
                    var crtFile = candidateCrt[0];
                    var keyFile = FindMatchingKeyFile(crtFile, directory, logger) ?? candidateKeys[0];
                    var generated = GeneratePfxAndLoad(hostWithoutPort, crtFile, keyFile, logger);
                    if (generated != null)
                    {
                        return generated;
                    }
                }
            }
            catch { }

            // 2. Search any .crt in the directory
            var crtFiles = Directory.GetFiles(directory, "*.crt", SearchOption.TopDirectoryOnly);

            if (crtFiles.Length == 0)
            {
                Log.Warn("No .crt files found in the directory");
            }
            else if (crtFiles.Length == 1)
            {
                // If there is a single .crt, assume it is the correct one
                var crtFile = crtFiles[0];
                Log.Info($"Single certificate found: {Path.GetFileName(crtFile)}");

                // Find its matching .key
                var keyFile = FindMatchingKeyFile(crtFile, directory, logger);

                if (keyFile != null)
                {
                    Log.Info($"Private key found: {Path.GetFileName(keyFile)}");
                    return LoadPemCertificate(crtFile, keyFile, logger);
                }
            }
            else
            {
                // Multiple .crt files, try to find a match with the domain
                Log.Info($"Found {crtFiles.Length} certificates:");

                foreach (var crtFile in crtFiles)
                {
                    var fileName = Path.GetFileNameWithoutExtension(crtFile).ToLowerInvariant();
                    Log.Info($"   - {Path.GetFileName(crtFile)}");

                    // Check if the file name contains parts of the domain
                    var domainParts = hostWithoutPort.Replace("www.", "").Replace("-", "_").Replace(".", "_").Split('_');

                    if (domainParts.Any(part => !string.IsNullOrEmpty(part) && fileName.Contains(part)))
                    {
                        Log.Info($"Match found: {Path.GetFileName(crtFile)}");

                        var keyFile = FindMatchingKeyFile(crtFile, directory, logger);
                        if (keyFile != null)
                        {
                            return LoadPemCertificate(crtFile, keyFile, logger);
                        }
                    }
                }
            }

            // 3. Search .pfx files
            var pfxFiles = Directory.GetFiles(directory, "*.pfx", SearchOption.TopDirectoryOnly);
            if (pfxFiles.Length > 0)
            {
                var pfxFile = pfxFiles[0];
                Log.Info($"PFX certificate found: {Path.GetFileName(pfxFile)}");

                try
                {
                    return new X509Certificate2(pfxFile, password, X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    Log.Error($"Error loading PFX certificate: {pfxFile}. {ex.Message}");
                }
            }

            // 4. Search .p12 files
            var p12Files = Directory.GetFiles(directory, "*.p12", SearchOption.TopDirectoryOnly);
            if (p12Files.Length > 0)
            {
                var p12File = p12Files[0];
                Log.Info($"P12 certificate found: {Path.GetFileName(p12File)}");

                try
                {
                    return new X509Certificate2(p12File, password, X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    Log.Error($"Error loading P12 certificate: {p12File}. {ex.Message}");
                }
            }

            Log.Warn($"Could not load certificates for '{host}' from directory");
            return null;
        }

        /// <summary>
        /// Try to load with the exact host name
        /// </summary>
        private static X509Certificate2? TryLoadExactMatch(string directory, string host, string? password, ILogger? logger)
        {
            // Look for PEM certificate (.crt + .key) with exact name
            var crtPath = Path.Combine(directory, $"{host}.crt");
            var keyPath = Path.Combine(directory, $"{host}.key");

            if (File.Exists(crtPath) && File.Exists(keyPath))
            {
                Log.Info("PEM certificates found (exact name):");
                Log.Info($"   CRT: {Path.GetFileName(crtPath)}");
                Log.Info($"   KEY: {Path.GetFileName(keyPath)}");
                return LoadPemCertificate(crtPath, keyPath, logger);
            }

            // Look for PFX certificate with exact name
            var pfxPath = Path.Combine(directory, $"{host}.pfx");
            if (File.Exists(pfxPath))
            {
                Log.Info($"PFX certificate found (exact name): {Path.GetFileName(pfxPath)}");
                try
                {
                    return new X509Certificate2(pfxPath, password, X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    Log.Error($"Error loading PFX certificate: {pfxPath}. {ex.Message}");
                }
            }

            // Look for P12 certificate with exact name
            var p12Path = Path.Combine(directory, $"{host}.p12");
            if (File.Exists(p12Path))
            {
                Log.Info($"P12 certificate found (exact name): {Path.GetFileName(p12Path)}");
                try
                {
                    return new X509Certificate2(p12Path, password, X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    Log.Error($"Error loading P12 certificate: {p12Path}. {ex.Message}");
                }
            }

            return null;
        }

        /// <summary>
        /// Find the .key file corresponding to a .crt
        /// </summary>
        private static string? FindMatchingKeyFile(string crtFile, string directory, ILogger? logger)
        {
            var baseName = Path.GetFileNameWithoutExtension(crtFile);

            // 1. Look for the same base name
            var expectedKeyFile = Path.Combine(directory, $"{baseName}.key");
            if (File.Exists(expectedKeyFile))
            {
                return expectedKeyFile;
            }

            // 2. Look for a file named "private.key" or "privatekey.key"
            var privateKeyFile = Path.Combine(directory, "private.key");
            if (File.Exists(privateKeyFile))
            {
                Log.Info("Using generic private key: private.key");
                return privateKeyFile;
            }

            privateKeyFile = Path.Combine(directory, "privatekey.key");
            if (File.Exists(privateKeyFile))
            {
                Log.Info("Using generic private key: privatekey.key");
                return privateKeyFile;
            }

            // 3. Look for any .key file in the directory
            var keyFiles = Directory.GetFiles(directory, "*.key", SearchOption.TopDirectoryOnly);
            if (keyFiles.Length == 1)
            {
                Log.Info($"Using the only private key found: {Path.GetFileName(keyFiles[0])}");
                return keyFiles[0];
            }
            else if (keyFiles.Length > 1)
            {
                Log.Warn($"Found {keyFiles.Length} .key files, cannot determine which one to use");
                foreach (var keyFile in keyFiles)
                {
                    Log.Warn($"   - {Path.GetFileName(keyFile)}");
                }
            }
            else
            {
                Log.Warn($"No .key file found for {Path.GetFileName(crtFile)}");
            }

            return null;
        }

        // Generate a PFX containing certificate + key + chain (if available) and load it
        private static X509Certificate2? GeneratePfxAndLoad(string host, string crtPath, string keyPath, ILogger? logger)
        {
            try
            {
                var directory = Path.GetDirectoryName(crtPath)!;
                var baseName = Path.GetFileNameWithoutExtension(crtPath);
                var hostName = host.Split(':')[0].ToLowerInvariant();

                // Possible CA bundle paths
                var caBundleByBase = Path.Combine(directory, $"{baseName}.ca-bundle");
                var caBundleByHost = Path.Combine(directory, $"{hostName}.ca-bundle");
                string? caBundlePath = null;
                if (File.Exists(caBundleByHost)) caBundlePath = caBundleByHost;
                else if (File.Exists(caBundleByBase)) caBundlePath = caBundleByBase;

                // Read leaf cert
                var leafPem = File.ReadAllText(crtPath);
                var leafCert = X509Certificate2.CreateFromPem(leafPem);

                // Read private key
                var keyPem = File.ReadAllText(keyPath);
                RSA? rsa = null; ECDsa? ecdsa = null;
                if (keyPem.Contains("BEGIN RSA PRIVATE KEY") || keyPem.Contains("BEGIN PRIVATE KEY"))
                {
                    rsa = RSA.Create();
                    rsa.ImportFromPem(keyPem);
                }
                else if (keyPem.Contains("BEGIN EC PRIVATE KEY"))
                {
                    ecdsa = ECDsa.Create();
                    ecdsa.ImportFromPem(keyPem);
                }
                else
                {
                    Log.Warn("Unrecognized private key type for PFX generation");
                    return null;
                }

                var leafWithKey = rsa != null ? leafCert.CopyWithPrivateKey(rsa) : leafCert.CopyWithPrivateKey(ecdsa!);

                // Validate key -> cert match
                if (rsa != null)
                {
                    using var pub = leafWithKey.GetRSAPublicKey();
                    if (pub == null)
                    {
                        Log.Error("RSA public key missing in certificate");
                        return null;
                    }
                    var pubParams = pub.ExportParameters(false);
                    var privParams = rsa.ExportParameters(false);
                    if (pubParams.Modulus == null || privParams.Modulus == null || !pubParams.Modulus.SequenceEqual(privParams.Modulus))
                    {
                        Log.Error("RSA private key does not match the certificate");
                        return null;
                    }
                }
                else if (ecdsa != null)
                {
                    using var pub = leafWithKey.GetECDsaPublicKey();
                    if (pub == null)
                    {
                        Log.Error("ECDSA public key missing in certificate");
                        return null;
                    }
                    var pubParams = pub.ExportParameters(false);
                    var privParams = ecdsa.ExportParameters(false);
                    if (pubParams.Q.X == null || pubParams.Q.Y == null || privParams.Q.X == null || privParams.Q.Y == null ||
                        !pubParams.Q.X.SequenceEqual(privParams.Q.X) || !pubParams.Q.Y.SequenceEqual(privParams.Q.Y))
                    {
                        Log.Error("ECDSA private key does not match the certificate");
                        return null;
                    }
                }

                // Build collection with chain
                var collection = new X509Certificate2Collection();
                collection.Add(leafWithKey);
                if (!string.IsNullOrEmpty(caBundlePath))
                {
                    Log.Info($"Using CA bundle: {Path.GetFileName(caBundlePath)}");
                    var caPem = File.ReadAllText(caBundlePath);
                    foreach (var ca in ParseCertificatesFromPem(caPem))
                    {
                        collection.Add(ca);
                    }
                }

                // Export to PFX and save using host name
                var pfxBytes = collection.Export(X509ContentType.Pkcs12, string.Empty);
                var outPath = Path.Combine(directory, $"{hostName}.pfx");
                File.WriteAllBytes(outPath, pfxBytes);
                Log.Info($"Dynamically generated PFX: {Path.GetFileName(outPath)}");

                // Load and return the generated PFX
                return new X509Certificate2(pfxBytes, string.Empty, X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                Log.Error($"Error generating PFX dynamically from PEM: {ex.Message}");
                return null;
            }
        }

        private static IEnumerable<X509Certificate2> ParseCertificatesFromPem(string pem)
        {
            var list = new List<X509Certificate2>();
            var sb = new StringBuilder();
            using var reader = new StringReader(pem);
            string? line;
            bool inside = false;
            while ((line = reader.ReadLine()) != null)
            {
                if (line.Contains("BEGIN CERTIFICATE"))
                {
                    inside = true;
                    sb.Clear();
                    sb.AppendLine(line);
                }
                else if (inside)
                {
                    sb.AppendLine(line);
                    if (line.Contains("END CERTIFICATE"))
                    {
                        inside = false;
                        try { list.Add(X509Certificate2.CreateFromPem(sb.ToString())); } catch { }
                    }
                }
            }
            return list;
        }

        /// <summary>
        /// Load a certificate from files (supports .pfx and .crt/.key)
        /// </summary>
        public static X509Certificate2? LoadCertificate(
            string? certPath,
            string? keyPath = null,
            string? password = null,
            ILogger? logger = null)
        {
            if (string.IsNullOrEmpty(certPath))
                return null;

            try
            {
                var extension = Path.GetExtension(certPath).ToLowerInvariant();

                if (extension == ".pfx" || extension == ".p12")
                {
                    // Load PFX certificate
                    Log.Info($"Loading PFX certificate: {certPath}");
                    return new X509Certificate2(certPath, password, X509KeyStorageFlags.Exportable);
                }
                else if (extension == ".crt" || extension == ".pem" || extension == ".cer")
                {
                    // Load PEM certificate (.crt + .key)
                    if (string.IsNullOrEmpty(keyPath))
                    {
                        Log.Warn(".crt certificate requires a .key file");
                        return null;
                    }

                    Log.Info($"Loading PEM certificate: {certPath} + {keyPath}");
                    return LoadPemCertificate(certPath, keyPath, logger);
                }
                else
                {
                    Log.Warn($"Unsupported certificate format: {extension}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Error loading certificate: {certPath}. {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Load a PEM certificate (.crt + .key)
        /// If a .ca-bundle exists, it is combined automatically to form the full chain
        /// </summary>
        private static X509Certificate2? LoadPemCertificate(string certPath, string keyPath, ILogger? logger)
        {
            try
            {
                // Read certificate
                var certPem = File.ReadAllText(certPath);

                // Combine with CA bundle if exists
                var directory = Path.GetDirectoryName(certPath);
                var baseName = Path.GetFileNameWithoutExtension(certPath);
                var caBundlePath = Path.Combine(directory!, $"{baseName}.ca-bundle");

                if (File.Exists(caBundlePath))
                {
                    Log.Info($"Found CA bundle: {Path.GetFileName(caBundlePath)}");
                    var caBundlePem = File.ReadAllText(caBundlePath);

                    // Combine certificate + CA bundle to form full chain
                    certPem = certPem.TrimEnd() + "\n" + caBundlePem.TrimEnd() + "\n";
                    Log.Info("Certificate chain combined automatically");
                }
                else
                {
                    Log.Info($"No CA bundle found (optional): {baseName}.ca-bundle");
                }

                var cert = X509Certificate2.CreateFromPem(certPem);

                // Read private key
                var keyPem = File.ReadAllText(keyPath);

                // Determine private key type
                RSA? rsa = null;
                ECDsa? ecdsa = null;

                if (keyPem.Contains("BEGIN RSA PRIVATE KEY") || keyPem.Contains("BEGIN PRIVATE KEY"))
                {
                    // RSA key
                    rsa = RSA.Create();
                    rsa.ImportFromPem(keyPem);
                    Log.Info("  -> Type: RSA");
                }
                else if (keyPem.Contains("BEGIN EC PRIVATE KEY"))
                {
                    // ECDSA key
                    ecdsa = ECDsa.Create();
                    ecdsa.ImportFromPem(keyPem);
                    Log.Info("  -> Type: ECDSA");
                }
                else
                {
                    Log.Warn("Unrecognized private key type");
                    return null;
                }

                // Combine certificate with private key
                X509Certificate2 certWithKey;
                if (rsa != null)
                {
                    certWithKey = cert.CopyWithPrivateKey(rsa);
                }
                else if (ecdsa != null)
                {
                    certWithKey = cert.CopyWithPrivateKey(ecdsa);
                }
                else
                {
                    return null;
                }

                // Re-import as PFX to ensure the private key is usable by SChannel/Kestrel on Windows
                var pfxBytes = certWithKey.Export(X509ContentType.Pkcs12, string.Empty);
                var materialized = new X509Certificate2(
                    pfxBytes,
                    string.Empty,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

                Log.Info("Certificate loaded successfully");
                Log.Info($"  -> Subject: {materialized.Subject}");
                Log.Info($"  -> Issuer: {materialized.Issuer}");
                Log.Info($"  -> Valid from: {materialized.NotBefore:yyyy-MM-dd}");
                Log.Info($"  -> Valid until: {materialized.NotAfter:yyyy-MM-dd}");
                Log.Info($"  -> Days remaining: {(materialized.NotAfter - DateTime.Now).Days}");

                return materialized;
            }
            catch (Exception ex)
            {
                Log.Error($"Error loading PEM certificate: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Verify if a certificate is valid
        /// </summary>
        public static bool IsCertificateValid(X509Certificate2 cert, ILogger? logger = null)
        {
            try
            {
                var now = DateTime.Now;

                if (now < cert.NotBefore)
                {
                    Log.Warn($"Certificate is not valid yet (valid from {cert.NotBefore:yyyy-MM-dd})");
                    return false;
                }

                if (now > cert.NotAfter)
                {
                    Log.Warn($"Certificate expired (expired on {cert.NotAfter:yyyy-MM-dd})");
                    return false;
                }

                var daysRemaining = (cert.NotAfter - now).Days;
                if (daysRemaining < 30)
                {
                    Log.Warn($"Certificate expires soon ({daysRemaining} days)");
                }

                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Error validating certificate: {ex.Message}");
                return false;
            }
        }
    }
}
