namespace Reversify.Models
{
    /// <summary>
    /// Modelo de configuración para un proxy inverso
    /// </summary>
    public class ProxyConfig
    {
        /// <summary>
        /// URL del DNS (ej: www.mipage1.com)
        /// </summary>
        public string DnsUrl { get; set; } = string.Empty;

        /// <summary>
        /// URL local a la que se redirigirá (ej: http://127.0.0.1:1111)
        /// </summary>
        public string LocalUrl { get; set; } = string.Empty;

        /// <summary>
        /// Directorio que contiene los certificados SSL/TLS (opcional)
        /// El sistema buscará automáticamente .crt/.key o .pfx con el mismo nombre que DnsUrl
        /// Ejemplo: C:\Certificates -> buscará www.midominio.com.crt + www.midominio.com.key
        /// </summary>
        public string? CertificatesDirectory { get; set; }

        /// <summary>
        /// Contraseña del certificado (opcional, solo para .pfx)
        /// </summary>
        public string? CertificatePassword { get; set; }

        /// <summary>
        /// Indica si está activo
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Nombre descriptivo de la configuración
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// ID único de la configuración
        /// </summary>
        public string Id { get; set; } = Guid.NewGuid().ToString();
    }
}
