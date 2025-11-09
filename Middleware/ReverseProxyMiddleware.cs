using Reversify.Services;
using System.Net;

namespace Reversify.Middleware
{
    /// <summary>
    /// Middleware personalizado de proxy inverso
    /// </summary>
    public class ReverseProxyMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ReverseProxyMiddleware> _logger;
        private readonly IHttpClientFactory _httpClientFactory;

        public ReverseProxyMiddleware(
            RequestDelegate next,
            ILogger<ReverseProxyMiddleware> logger,
            IHttpClientFactory httpClientFactory)
        {
            _next = next;
            _logger = logger;
            _httpClientFactory = httpClientFactory;
        }

        public async Task InvokeAsync(HttpContext context, IProxyService proxyService)
        {
            var host = context.Request.Host.Host;
            var fullUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}";
            var rawTarget = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>()?.RawTarget ?? string.Empty;
            var proxyConfig = proxyService.GetProxyByHost(host);

            // Guard: evitar servir contenido local cuando el host no está configurado
            if (proxyConfig == null || !proxyConfig.Enabled)
            {
                var isLocalHost = string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
                                  || string.Equals(host, "127.0.0.1", StringComparison.OrdinalIgnoreCase)
                                  || string.Equals(host, "::1", StringComparison.OrdinalIgnoreCase);
                if (!isLocalHost)
                {
                    _logger.LogWarning($"Host no configurado para proxy: {host}. 404 para evitar servir contenido local.");
                    context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                    await context.Response.WriteAsync("404 - Host no configurado en el proxy inverso");
                    return;
                }
            }

            // Si no hay configuración de proxy para este host, continuar con la siguiente middleware
            if (proxyConfig == null || !proxyConfig.Enabled)
            {
                _logger.LogInformation($"📄 [LOCAL] {context.Request.Method} {fullUrl} -> Procesando localmente");
                await _next(context);
                return;
            }

            // HAY PROXY CONFIGURADO - Redirigir la petición
            var targetUrl = $"{proxyConfig.LocalUrl}{context.Request.Path}{context.Request.QueryString}";

            // Diagnóstico adicional de HTTPS y encabezados a enviar al backend
            {
                var schemeLabel = context.Request.IsHttps ? "HTTPS" : "HTTP";
                _logger.LogInformation($"Diagnóstico: scheme={schemeLabel} IsHttps={context.Request.IsHttps}");
                var detectedProto = context.Request.IsHttps ? "https" : "http";
                var detectedPort = context.Request.Host.Port ?? (context.Request.IsHttps ? 443 : 80);
                _logger.LogInformation($"Diagnóstico: Forwarded preview proto={detectedProto}; host={host}; port={detectedPort}");
            }

            _logger.LogInformation($"");
            _logger.LogInformation($"{'═',60}");
            _logger.LogInformation($"🔀 SOLICITUD DE PROXY");
            _logger.LogInformation($"{'─',60}");
            _logger.LogInformation($"  📥 Origen:  {context.Request.Method} {fullUrl}");
            _logger.LogInformation($"  📤 Destino: {targetUrl}");
            _logger.LogInformation($"  🌐 Host:    {host}");
            _logger.LogInformation($"  🔗 Config:  {proxyConfig.Name}");
            _logger.LogInformation($"{'═',60}");
            _logger.LogInformation($"");

            try
            {
                await ProxyRequestAsync(context, proxyConfig.LocalUrl);

                _logger.LogInformation($"✅ [PROXY] Completado: {context.Request.Method} {fullUrl} -> {context.Response.StatusCode}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"❌ [PROXY] Error: {context.Request.Method} {fullUrl}");
                context.Response.StatusCode = (int)HttpStatusCode.BadGateway;
                await context.Response.WriteAsync("502 Bad Gateway - Error al conectar con el servidor de destino");
            }
        }

        private async Task ProxyRequestAsync(HttpContext context, string targetUrl)
        {
            // Construir la URL de destino
            var targetUri = new Uri(new Uri(targetUrl), context.Request.Path + context.Request.QueryString);

            _logger.LogDebug($"   → Destino completo: {targetUri}");

            // Crear la petición HTTP
            var httpClient = _httpClientFactory.CreateClient("ProxyClient");
            var requestMessage = new HttpRequestMessage();
            var method = context.Request.Method;

            // Establecer el método HTTP
            requestMessage.Method = new HttpMethod(method);
            requestMessage.RequestUri = targetUri;

            // Copiar headers (excepto los que no se deben reenviar ni los de contenido)
            foreach (var header in context.Request.Headers)
            {
                if (!ShouldSkipHeader(header.Key))
                {
                    if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
                    {
                        // Usar el host del destino
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
            // RFC 7239 header (algunos backends lo prefieren)
            requestMessage.Headers.TryAddWithoutValidation("Forwarded", $"for={clientIp};proto={originalProto};host={originalHost}");

            // Copiar el body si existe
            // Cuerpo y headers de contenido: reenviar de forma laxa para evitar errores de formato
            var methodHasBody = string.Equals(context.Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
                                || string.Equals(context.Request.Method, "PUT", StringComparison.OrdinalIgnoreCase)
                                || string.Equals(context.Request.Method, "PATCH", StringComparison.OrdinalIgnoreCase)
                                || string.Equals(context.Request.Method, "DELETE", StringComparison.OrdinalIgnoreCase);

            if ((context.Request.ContentLength ?? 0) > 0 || methodHasBody)
            {
                var streamContent = new StreamContent(context.Request.Body);

                // Copiar todos los headers de contenido como están (sin validación estricta)
                foreach (var header in context.Request.Headers)
                {
                    if (header.Key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
                    {
                        // Evitar Content-Length: lo gestiona HttpClient/StreamContent
                        if (header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                            continue;
                        streamContent.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                    }
                }
                requestMessage.Content = streamContent;
            }

            // Enviar la petición al servidor de destino
            var responseMessage = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);

            _logger.LogDebug($"   ← Respuesta: {(int)responseMessage.StatusCode} {responseMessage.ReasonPhrase}");

            // Copiar el status code
            context.Response.StatusCode = (int)responseMessage.StatusCode;

            // Copiar headers de respuesta (excepto los que no se deben reenviar)
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

            // Ajustes para SSE (Server-Sent Events)
            var contentType = responseMessage.Content.Headers.ContentType?.MediaType;
            var isSse = !string.IsNullOrEmpty(contentType) &&
                        contentType.Equals("text/event-stream", StringComparison.OrdinalIgnoreCase);
            if (isSse)
            {
                // Asegurar cabeceras que evitan buffering
                if (!context.Response.Headers.ContainsKey("Cache-Control"))
                {
                    context.Response.Headers["Cache-Control"] = "no-cache";
                }
                // Desactivar buffering en proxies intermedios comunes
                context.Response.Headers["X-Accel-Buffering"] = "no";
            }

            // Copiar el body de la respuesta
            await responseMessage.Content.CopyToAsync(context.Response.Body);
        }

        private bool ShouldSkipHeader(string headerName)
        {
            // Headers que no se deben reenviar
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
            // Headers de respuesta que no se deben reenviar
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
    /// Extensión para agregar el middleware de proxy
    /// </summary>
    public static class ReverseProxyMiddlewareExtensions
    {
        public static IApplicationBuilder UseReverseProxy(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ReverseProxyMiddleware>();
        }
    }
}






