using Reversify.Models;

namespace Reversify.Modules
{
    /// <summary>
    /// Middleware that integrates attack detection modules
    /// </summary>
    public class AttackDetectionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IEnumerable<IAttackDetectionModule> _detectionModules;

        public AttackDetectionMiddleware(
            RequestDelegate next,
            IEnumerable<IAttackDetectionModule> detectionModules)
        {
            _next = next;
            _detectionModules = detectionModules;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Run all detection modules
            foreach (var module in _detectionModules)
            {
                try
                {
                    var result = await module.DetectAsync(context);

                    if (result != null && result.IsAttack)
                    {
                        Log.Warn(
                            $"[{module.ModuleName}] Attack detected: {result.AttackType} | IP: {result.IpAddress} | Reason: {result.Reason}");

                        // Block the request
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
                    Log.Error($"Error in detection module: {module.ModuleName}. {ex.Message}");
                }
            }

            // If no attack is detected, continue to the next middleware
            await _next(context);
        }
    }

    /// <summary>
    /// Extension to add attack detection middleware
    /// </summary>
    public static class AttackDetectionMiddlewareExtensions
    {
        public static IApplicationBuilder UseAttackDetection(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<AttackDetectionMiddleware>();
        }
    }
}
