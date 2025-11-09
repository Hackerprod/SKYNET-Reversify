using ProxInv.Models;

namespace ProxInv.Modules
{
    /// <summary>
    /// Interfaz base para módulos de detección de ataques
    /// </summary>
    public interface IAttackDetectionModule
    {
        string ModuleName { get; }
        Task<AttackDetectionResult?> DetectAsync(HttpContext context);
        void Reset();
    }
}
