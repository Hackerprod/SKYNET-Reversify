using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Reversify.Services
{
    /// <summary>
    /// Servicio para cargar certificados SSL en diferentes formatos
    /// </summary>
    public static class CertificateLoader
    {
        /// <summary>
        /// Verifica si el certificado coincide con el host solicitado (CN o SANs)
        /// </summary>
        public static bool MatchesHost(X509Certificate2 cert, string host)
        {
            if (string.IsNullOrEmpty(host)) return false;

            try
            {
                var target = host.Split(':')[0].Trim().ToLowerInvariant();

                // 1) Revisar Subject Alternative Name (SAN) DNS entries (OID 2.5.29.17)
                foreach (var ext in cert.Extensions)
                {
                    if (ext.Oid?.Value == "2.5.29.17")
                    {
                        // System.Security.Cryptography.AsnEncodedData.Format(true) devuelve los DNS en texto
                        var formatted = ext.Format(true);
                        // Buscar líneas como: DNS Name=example.com
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

                // 2) Fallback: CN del Subject
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

            // Soportar comodines tipo *.dominio.com
            if (pattern.StartsWith("*.", StringComparison.Ordinal) && host.Length > 2)
            {
                var suffix = pattern.Substring(1); // ".dominio.com"
                return host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) && host.Count(c => c == '.') >= 2;
            }

            return false;
        }
        /// <summary>
        /// Carga un certificado desde un directorio buscando automáticamente por extensión
        /// Busca cualquier archivo .crt + .key, .pfx o .p12 en el directorio
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
                logger?.LogWarning($"⚠️  El directorio de certificados no existe: {directory}");
                return null;
            }

            logger?.LogInformation($"📂 Buscando certificados en: {directory}");

            // Normalizar el host (sin puerto)
            var hostWithoutPort = host.Split(':')[0].ToLowerInvariant();

            // 1. Intentar con el nombre exacto del host primero
            var cert = TryLoadExactMatch(directory, hostWithoutPort, password, logger);
            if (cert != null)
                return cert;

            // 1.5 Si no hay {host}.pfx pero existe un único .crt y alguna .key, generamos dinámicamente un .pfx con cadena y lo usamos
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

            // 2. Buscar cualquier archivo .crt en el directorio
            var crtFiles = Directory.GetFiles(directory, "*.crt", SearchOption.TopDirectoryOnly);

            if (crtFiles.Length == 0)
            {
                logger?.LogWarning($"⚠️  No se encontró ningún archivo .crt en el directorio");
            }
            else if (crtFiles.Length == 1)
            {
                // Si hay un solo .crt, asumimos que es el correcto
                var crtFile = crtFiles[0];
                logger?.LogInformation($"📜 Encontrado certificado único: {Path.GetFileName(crtFile)}");

                // Buscar su .key correspondiente
                var keyFile = FindMatchingKeyFile(crtFile, directory, logger);

                if (keyFile != null)
                {
                    logger?.LogInformation($"🔑 Encontrada clave privada: {Path.GetFileName(keyFile)}");
                    return LoadPemCertificate(crtFile, keyFile, logger);
                }
            }
            else
            {
                // Múltiples .crt, intentar encontrar el que coincida con el dominio
                logger?.LogInformation($"📜 Encontrados {crtFiles.Length} certificados:");

                foreach (var crtFile in crtFiles)
                {
                    var fileName = Path.GetFileNameWithoutExtension(crtFile).ToLowerInvariant();
                    logger?.LogInformation($"   - {Path.GetFileName(crtFile)}");

                    // Verificar si el nombre del archivo contiene partes del dominio
                    var domainParts = hostWithoutPort.Replace("www.", "").Replace("-", "_").Replace(".", "_").Split('_');

                    if (domainParts.Any(part => !string.IsNullOrEmpty(part) && fileName.Contains(part)))
                    {
                        logger?.LogInformation($"✅ Coincidencia encontrada: {Path.GetFileName(crtFile)}");

                        var keyFile = FindMatchingKeyFile(crtFile, directory, logger);
                        if (keyFile != null)
                        {
                            return LoadPemCertificate(crtFile, keyFile, logger);
                        }
                    }
                }
            }

            // 3. Buscar archivos .pfx
            var pfxFiles = Directory.GetFiles(directory, "*.pfx", SearchOption.TopDirectoryOnly);
            if (pfxFiles.Length > 0)
            {
                var pfxFile = pfxFiles[0];
                logger?.LogInformation($"📜 Certificado PFX encontrado: {Path.GetFileName(pfxFile)}");

                try
                {
                    return new X509Certificate2(pfxFile, password, X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    logger?.LogError(ex, $"❌ Error al cargar certificado PFX: {pfxFile}");
                }
            }

            // 4. Buscar archivos .p12
            var p12Files = Directory.GetFiles(directory, "*.p12", SearchOption.TopDirectoryOnly);
            if (p12Files.Length > 0)
            {
                var p12File = p12Files[0];
                logger?.LogInformation($"📜 Certificado P12 encontrado: {Path.GetFileName(p12File)}");

                try
                {
                    return new X509Certificate2(p12File, password, X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    logger?.LogError(ex, $"❌ Error al cargar certificado P12: {p12File}");
                }
            }

            logger?.LogWarning($"⚠️  No se pudieron cargar certificados para '{host}' desde el directorio");
            return null;
        }

        /// <summary>
        /// Intenta cargar con el nombre exacto del host
        /// </summary>
        private static X509Certificate2? TryLoadExactMatch(string directory, string host, string? password, ILogger? logger)
        {
            // Buscar certificado PEM (.crt + .key) con nombre exacto
            var crtPath = Path.Combine(directory, $"{host}.crt");
            var keyPath = Path.Combine(directory, $"{host}.key");

            if (File.Exists(crtPath) && File.Exists(keyPath))
            {
                logger?.LogInformation($"📜 Certificados PEM encontrados (nombre exacto):");
                logger?.LogInformation($"   CRT: {Path.GetFileName(crtPath)}");
                logger?.LogInformation($"   KEY: {Path.GetFileName(keyPath)}");
                return LoadPemCertificate(crtPath, keyPath, logger);
            }

            // Buscar certificado PFX con nombre exacto
            var pfxPath = Path.Combine(directory, $"{host}.pfx");
            if (File.Exists(pfxPath))
            {
                logger?.LogInformation($"📜 Certificado PFX encontrado (nombre exacto): {Path.GetFileName(pfxPath)}");
                try
                {
                    return new X509Certificate2(pfxPath, password, X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    logger?.LogError(ex, $"❌ Error al cargar certificado PFX: {pfxPath}");
                }
            }

            // Buscar certificado P12 con nombre exacto
            var p12Path = Path.Combine(directory, $"{host}.p12");
            if (File.Exists(p12Path))
            {
                logger?.LogInformation($"📜 Certificado P12 encontrado (nombre exacto): {Path.GetFileName(p12Path)}");
                try
                {
                    return new X509Certificate2(p12Path, password, X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    logger?.LogError(ex, $"❌ Error al cargar certificado P12: {p12Path}");
                }
            }

            return null;
        }

        /// <summary>
        /// Busca el archivo .key que corresponde a un .crt
        /// </summary>
        private static string? FindMatchingKeyFile(string crtFile, string directory, ILogger? logger)
        {
            var baseName = Path.GetFileNameWithoutExtension(crtFile);

            // 1. Buscar con el mismo nombre base
            var expectedKeyFile = Path.Combine(directory, $"{baseName}.key");
            if (File.Exists(expectedKeyFile))
            {
                return expectedKeyFile;
            }

            // 2. Buscar archivo llamado "private.key" o "privatekey.key"
            var privateKeyFile = Path.Combine(directory, "private.key");
            if (File.Exists(privateKeyFile))
            {
                logger?.LogInformation($"🔑 Usando clave privada genérica: private.key");
                return privateKeyFile;
            }

            privateKeyFile = Path.Combine(directory, "privatekey.key");
            if (File.Exists(privateKeyFile))
            {
                logger?.LogInformation($"🔑 Usando clave privada genérica: privatekey.key");
                return privateKeyFile;
            }

            // 3. Buscar cualquier archivo .key en el directorio
            var keyFiles = Directory.GetFiles(directory, "*.key", SearchOption.TopDirectoryOnly);
            if (keyFiles.Length == 1)
            {
                logger?.LogInformation($"🔑 Usando única clave privada encontrada: {Path.GetFileName(keyFiles[0])}");
                return keyFiles[0];
            }
            else if (keyFiles.Length > 1)
            {
                logger?.LogWarning($"⚠️  Se encontraron {keyFiles.Length} archivos .key, no se puede determinar cuál usar");
                foreach (var keyFile in keyFiles)
                {
                    logger?.LogWarning($"   - {Path.GetFileName(keyFile)}");
                }
            }
            else
            {
                logger?.LogWarning($"⚠️  No se encontró ningún archivo .key para {Path.GetFileName(crtFile)}");
            }

            return null;
        }

        // Genera un PFX conteniendo el certificado + clave + cadena (si existe) y lo carga
        private static X509Certificate2? GeneratePfxAndLoad(string host, string crtPath, string keyPath, ILogger? logger)
        {
            try
            {
                var directory = Path.GetDirectoryName(crtPath)!;
                var baseName = Path.GetFileNameWithoutExtension(crtPath);
                var hostName = host.Split(':')[0].ToLowerInvariant();

                // Rutas posibles de CA bundle
                var caBundleByBase = Path.Combine(directory, $"{baseName}.ca-bundle");
                var caBundleByHost = Path.Combine(directory, $"{hostName}.ca-bundle");
                string? caBundlePath = null;
                if (File.Exists(caBundleByHost)) caBundlePath = caBundleByHost;
                else if (File.Exists(caBundleByBase)) caBundlePath = caBundleByBase;

                // Leer leaf cert
                var leafPem = File.ReadAllText(crtPath);
                var leafCert = X509Certificate2.CreateFromPem(leafPem);

                // Leer clave privada
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
                    logger?.LogWarning("Tipo de clave privada no reconocido para generar PFX");
                    return null;
                }

                var leafWithKey = rsa != null ? leafCert.CopyWithPrivateKey(rsa) : leafCert.CopyWithPrivateKey(ecdsa!);

                // Validar correspondencia key ↔ cert
                if (rsa != null)
                {
                    using var pub = leafWithKey.GetRSAPublicKey();
                    if (pub == null)
                    {
                        logger?.LogError("Clave pública RSA inexistente en el certificado");
                        return null;
                    }
                    var pubParams = pub.ExportParameters(false);
                    var privParams = rsa.ExportParameters(false);
                    if (pubParams.Modulus == null || privParams.Modulus == null || !pubParams.Modulus.SequenceEqual(privParams.Modulus))
                    {
                        logger?.LogError("La clave privada RSA no corresponde al certificado");
                        return null;
                    }
                }
                else if (ecdsa != null)
                {
                    using var pub = leafWithKey.GetECDsaPublicKey();
                    if (pub == null)
                    {
                        logger?.LogError("Clave pública ECDSA inexistente en el certificado");
                        return null;
                    }
                    var pubParams = pub.ExportParameters(false);
                    var privParams = ecdsa.ExportParameters(false);
                    if (pubParams.Q.X == null || pubParams.Q.Y == null || privParams.Q.X == null || privParams.Q.Y == null ||
                        !pubParams.Q.X.SequenceEqual(privParams.Q.X) || !pubParams.Q.Y.SequenceEqual(privParams.Q.Y))
                    {
                        logger?.LogError("La clave privada ECDSA no corresponde al certificado");
                        return null;
                    }
                }

                // Construir colección con cadena
                var collection = new X509Certificate2Collection();
                collection.Add(leafWithKey);
                if (!string.IsNullOrEmpty(caBundlePath))
                {
                    logger?.LogInformation($"Usando CA bundle: {Path.GetFileName(caBundlePath)}");
                    var caPem = File.ReadAllText(caBundlePath);
                    foreach (var ca in ParseCertificatesFromPem(caPem))
                    {
                        collection.Add(ca);
                    }
                }

                // Exportar a PFX y guardar con nombre del host
                var pfxBytes = collection.Export(X509ContentType.Pkcs12, string.Empty);
                var outPath = Path.Combine(directory, $"{hostName}.pfx");
                File.WriteAllBytes(outPath, pfxBytes);
                logger?.LogInformation($"PFX generado dinámicamente: {Path.GetFileName(outPath)}");

                // Cargar el PFX recién generado y devolverlo
                return new X509Certificate2(pfxBytes, string.Empty, X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Error generando PFX dinámicamente desde PEM");
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
        /// Carga un certificado desde archivos (soporta .pfx y .crt/.key)
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
                    // Cargar certificado PFX
                    logger?.LogInformation($"📜 Cargando certificado PFX: {certPath}");
                    return new X509Certificate2(certPath, password, X509KeyStorageFlags.Exportable);
                }
                else if (extension == ".crt" || extension == ".pem" || extension == ".cer")
                {
                    // Cargar certificado PEM (.crt + .key)
                    if (string.IsNullOrEmpty(keyPath))
                    {
                        logger?.LogWarning($"⚠️  Certificado .crt requiere archivo .key");
                        return null;
                    }

                    logger?.LogInformation($"📜 Cargando certificado PEM: {certPath} + {keyPath}");
                    return LoadPemCertificate(certPath, keyPath, logger);
                }
                else
                {
                    logger?.LogWarning($"⚠️  Formato de certificado no soportado: {extension}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, $"❌ Error al cargar certificado: {certPath}");
                return null;
            }
        }

        /// <summary>
        /// Carga un certificado en formato PEM (.crt + .key)
        /// Si existe un .ca-bundle, lo combina automáticamente para formar la cadena completa
        /// </summary>
        private static X509Certificate2? LoadPemCertificate(string certPath, string keyPath, ILogger? logger)
        {
            try
            {
                // Leer el certificado
                var certPem = File.ReadAllText(certPath);

                // Buscar y combinar con CA bundle si existe
                var directory = Path.GetDirectoryName(certPath);
                var baseName = Path.GetFileNameWithoutExtension(certPath);
                var caBundlePath = Path.Combine(directory!, $"{baseName}.ca-bundle");

                if (File.Exists(caBundlePath))
                {
                    logger?.LogInformation($"🔗 Encontrado CA bundle: {Path.GetFileName(caBundlePath)}");
                    var caBundlePem = File.ReadAllText(caBundlePath);

                    // Combinar certificado + CA bundle para formar la cadena completa
                    certPem = certPem.TrimEnd() + "\n" + caBundlePem.TrimEnd() + "\n";
                    logger?.LogInformation($"✅ Cadena de certificados combinada automáticamente");
                }
                else
                {
                    logger?.LogDebug($"ℹ️  No se encontró CA bundle (opcional): {baseName}.ca-bundle");
                }

                var cert = X509Certificate2.CreateFromPem(certPem);

                // Leer la clave privada
                var keyPem = File.ReadAllText(keyPath);

                // Determinar el tipo de clave privada
                RSA? rsa = null;
                ECDsa? ecdsa = null;

                if (keyPem.Contains("BEGIN RSA PRIVATE KEY") || keyPem.Contains("BEGIN PRIVATE KEY"))
                {
                    // Clave RSA
                    rsa = RSA.Create();
                    rsa.ImportFromPem(keyPem);
                    logger?.LogDebug("  → Tipo: RSA");
                }
                else if (keyPem.Contains("BEGIN EC PRIVATE KEY"))
                {
                    // Clave ECDSA
                    ecdsa = ECDsa.Create();
                    ecdsa.ImportFromPem(keyPem);
                    logger?.LogDebug("  → Tipo: ECDSA");
                }
                else
                {
                    logger?.LogWarning($"⚠️  Tipo de clave privada no reconocido");
                    return null;
                }

                // Combinar certificado con clave privada
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

                logger?.LogInformation($"✅ Certificado cargado correctamente");
                logger?.LogInformation($"  → Subject: {certWithKey.Subject}");
                logger?.LogInformation($"  → Issuer: {certWithKey.Issuer}");
                logger?.LogInformation($"  → Válido desde: {certWithKey.NotBefore:yyyy-MM-dd}");
                logger?.LogInformation($"  → Válido hasta: {certWithKey.NotAfter:yyyy-MM-dd}");
                logger?.LogInformation($"  → Días restantes: {(certWithKey.NotAfter - DateTime.Now).Days}");

                return certWithKey;
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, $"❌ Error al cargar certificado PEM");
                return null;
            }
        }

        /// <summary>
        /// Verifica si un certificado es válido
        /// </summary>
        public static bool IsCertificateValid(X509Certificate2 cert, ILogger? logger = null)
        {
            try
            {
                var now = DateTime.Now;

                if (now < cert.NotBefore)
                {
                    logger?.LogWarning($"⚠️  Certificado aún no es válido (válido desde {cert.NotBefore:yyyy-MM-dd})");
                    return false;
                }

                if (now > cert.NotAfter)
                {
                    logger?.LogWarning($"⚠️  Certificado expirado (expiró el {cert.NotAfter:yyyy-MM-dd})");
                    return false;
                }

                var daysRemaining = (cert.NotAfter - now).Days;
                if (daysRemaining < 30)
                {
                    logger?.LogWarning($"⚠️  Certificado expira pronto ({daysRemaining} días)");
                }

                return true;
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "❌ Error al validar certificado");
                return false;
            }
        }
    }
}
