using ProxInv.Models;

namespace ProxInv.Modules
{
    /// <summary>
    /// Middleware que integra los módulos de detección de ataques
    /// </summary>
    public class AttackDetectionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IEnumerable<IAttackDetectionModule> _detectionModules;
        private readonly ILogger<AttackDetectionMiddleware> _logger;

        public AttackDetectionMiddleware(
            RequestDelegate next,
            IEnumerable<IAttackDetectionModule> detectionModules,
            ILogger<AttackDetectionMiddleware> logger)
        {
            _next = next;
            _detectionModules = detectionModules;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Ejecutar todos los módulos de detección
            foreach (var module in _detectionModules)
            {
                try
                {
                    var result = await module.DetectAsync(context);

                    if (result != null && result.IsAttack)
                    {
                        _logger.LogWarning(
                            $"[{module.ModuleName}] Ataque detectado: {result.AttackType} | IP: {result.IpAddress} | Razón: {result.Reason}");

                        // Bloquear la solicitud
                        context.Response.StatusCode = 429; // Too Many Requests
                        context.Response.Headers["Retry-After"] = "60";
                        await context.Response.WriteAsJsonAsync(new
                        {
                            error = "Too Many Requests",
                            message = "Solicitud bloqueada por medidas de seguridad",
                            details = result.Reason
                        });

                        return;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error en módulo de detección: {module.ModuleName}");
                }
            }

            // Si no se detectó ningún ataque, continuar con la siguiente middleware
            await _next(context);
        }
    }

    /// <summary>
    /// Extensión para agregar el middleware de detección de ataques
    /// </summary>
    public static class AttackDetectionMiddlewareExtensions
    {
        public static IApplicationBuilder UseAttackDetection(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<AttackDetectionMiddleware>();
        }
    }
}
