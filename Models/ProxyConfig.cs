namespace Reversify.Models
{
    /// <summary>
    /// Reverse proxy configuration model
    /// </summary>
    public class ProxyConfig
    {
        /// <summary>
        /// DNS URL (e.g., www.mypage1.com)
        /// </summary>
        public string DnsUrl { get; set; } = string.Empty;

        /// <summary>
        /// Local URL to forward to (e.g., http://127.0.0.1:1111)
        /// </summary>
        public string LocalUrl { get; set; } = string.Empty;

        /// <summary>
        /// Directory containing SSL/TLS certificates (optional)
        /// The system will automatically look for .crt/.key or .pfx with the same name as DnsUrl
        /// Example: C:\Certificates -> will look for www.mydomain.com.crt + www.mydomain.com.key
        /// </summary>
        public string? CertificatesDirectory { get; set; }

        /// <summary>
        /// Certificate password (optional, .pfx only)
        /// </summary>
        public string? CertificatePassword { get; set; }

        /// <summary>
        /// Indicates whether it is active
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Descriptive configuration name
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Unique configuration ID
        /// </summary>
        public string Id { get; set; } = Guid.NewGuid().ToString();
    }
}
