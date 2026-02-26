using Reversify.Services;
using System.Net;

namespace Reversify.Middleware
{
    /// <summary>
    /// Custom reverse proxy middleware
    /// </summary>
    public class ReverseProxyMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IHttpClientFactory _httpClientFactory;

        public ReverseProxyMiddleware(
            RequestDelegate next,
            IHttpClientFactory httpClientFactory)
        {
            _next = next;
            _httpClientFactory = httpClientFactory;
        }

        public async Task InvokeAsync(HttpContext context, IProxyService proxyService)
        {
            var host = context.Request.Host.Host;
            var path = context.Request.Path;
            var fullUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}";
            var proxyConfig = proxyService.GetProxyByHost(host);

            // Guard: avoid serving local content when the host is not configured
            if (proxyConfig == null || !proxyConfig.Enabled)
            {
                var isLocalHost = string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
                                  || string.Equals(host, "127.0.0.1", StringComparison.OrdinalIgnoreCase)
                                  || string.Equals(host, "::1", StringComparison.OrdinalIgnoreCase);
                if (!isLocalHost)
                {
                    Log.Warn($"Host not configured for proxy: {host}. Returning 404 to avoid serving local content.");
                    context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                    await context.Response.WriteAsync("404 - Host no configurado en el proxy inverso");
                    return;
                }
            }

            // If there is no proxy config for this host, continue to the next middleware
            if (proxyConfig == null || !proxyConfig.Enabled)
            {
                await _next(context);
                return;
            }

            // Proxy is configured - forward the request
            var targetUrl = $"{proxyConfig.LocalUrl}{context.Request.Path}{context.Request.QueryString}";

            try
            {
                await ProxyRequestAsync(context, proxyConfig.LocalUrl);

                Log.Info($"[PROXY] {context.Request.Method} {fullUrl} -> {targetUrl} ({context.Response.StatusCode})");
            }
            catch (Exception ex)
            {
                Log.Error($"[PROXY] Error: {context.Request.Method} {fullUrl}. {ex.Message}");
                context.Response.StatusCode = (int)HttpStatusCode.BadGateway;
                await context.Response.WriteAsync("502 Bad Gateway - Error al conectar con el servidor de destino");
            }
        }

        private async Task ProxyRequestAsync(HttpContext context, string targetUrl)
        {
            // Build target URL
            var targetUri = new Uri(new Uri(targetUrl), context.Request.Path + context.Request.QueryString);

            // Create HTTP request
            var httpClient = _httpClientFactory.CreateClient("ProxyClient");
            var requestMessage = new HttpRequestMessage();
            var method = context.Request.Method;

            // Set HTTP method
            requestMessage.Method = new HttpMethod(method);
            requestMessage.RequestUri = targetUri;

            // Copy headers (except those that should not be forwarded or content headers)
            foreach (var header in context.Request.Headers)
            {
                if (!ShouldSkipHeader(header.Key))
                {
                    if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
                    {
                        // Use target host
                        requestMessage.Headers.TryAddWithoutValidation(header.Key, new Uri(targetUrl).Host);
                    }
                    else if (!header.Key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
                    {
                        requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                    }
                }
            }

            // Add standard proxy headers so backend knows original client/scheme
            var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
            var originalHost = context.Request.Host.Host;
            var originalProto = context.Request.IsHttps ? "https" : "http";
            var originalPort = context.Request.Host.Port ?? (context.Request.IsHttps ? 443 : 80);

            requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-For", clientIp);
            requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-Host", originalHost);
            requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-Proto", originalProto);
            requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-Port", originalPort.ToString());
            // RFC 7239 header (some backends prefer it)
            requestMessage.Headers.TryAddWithoutValidation("Forwarded", $"for={clientIp};proto={originalProto};host={originalHost}");

            // Copy body if present
            // Content body and headers: forward loosely to avoid formatting errors
            var methodHasBody = string.Equals(context.Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
                                || string.Equals(context.Request.Method, "PUT", StringComparison.OrdinalIgnoreCase)
                                || string.Equals(context.Request.Method, "PATCH", StringComparison.OrdinalIgnoreCase)
                                || string.Equals(context.Request.Method, "DELETE", StringComparison.OrdinalIgnoreCase);

            if ((context.Request.ContentLength ?? 0) > 0 || methodHasBody)
            {
                var streamContent = new StreamContent(context.Request.Body);

                // Copy all content headers as-is (no strict validation)
                foreach (var header in context.Request.Headers)
                {
                    if (header.Key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
                    {
                        // Avoid Content-Length: handled by HttpClient/StreamContent
                        if (header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                            continue;
                        streamContent.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                    }
                }
                requestMessage.Content = streamContent;
            }

            // Send request to target server
            var responseMessage = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);

            // Copy status code
            context.Response.StatusCode = (int)responseMessage.StatusCode;

            // Copy response headers (except those that should not be forwarded)
            foreach (var header in responseMessage.Headers)
            {
                if (!ShouldSkipResponseHeader(header.Key))
                {
                    context.Response.Headers[header.Key] = header.Value.ToArray();
                }
            }

            foreach (var header in responseMessage.Content.Headers)
            {
                if (!ShouldSkipResponseHeader(header.Key))
                {
                    context.Response.Headers[header.Key] = header.Value.ToArray();
                }
            }

            // Adjustments for SSE (Server-Sent Events)
            var contentType = responseMessage.Content.Headers.ContentType?.MediaType;
            var isSse = !string.IsNullOrEmpty(contentType) &&
                        contentType.Equals("text/event-stream", StringComparison.OrdinalIgnoreCase);
            if (isSse)
            {
                // Ensure headers that avoid buffering
                if (!context.Response.Headers.ContainsKey("Cache-Control"))
                {
                    context.Response.Headers["Cache-Control"] = "no-cache";
                }
                // Disable buffering in common intermediate proxies
                context.Response.Headers["X-Accel-Buffering"] = "no";
            }

            // Copy response body
            await responseMessage.Content.CopyToAsync(context.Response.Body);
        }

        private bool ShouldSkipHeader(string headerName)
        {
            // Headers that should not be forwarded
            var skipHeaders = new[]
            {
                "Connection",
                "Transfer-Encoding",
                "Keep-Alive",
                "Upgrade"
            };

            return skipHeaders.Any(h => h.Equals(headerName, StringComparison.OrdinalIgnoreCase));
        }

        private bool ShouldSkipResponseHeader(string headerName)
        {
            // Response headers that should not be forwarded
            var skipHeaders = new[]
            {
                "Transfer-Encoding",
                "Connection",
                "Keep-Alive",
                "Upgrade"
            };

            return skipHeaders.Any(h => h.Equals(headerName, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// Extension to add the proxy middleware
    /// </summary>
    public static class ReverseProxyMiddlewareExtensions
    {
        public static IApplicationBuilder UseReverseProxy(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ReverseProxyMiddleware>();
        }
    }
}
