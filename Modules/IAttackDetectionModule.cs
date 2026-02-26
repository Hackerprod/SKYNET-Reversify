using Reversify.Models;

namespace Reversify.Modules
{
    /// <summary>
    /// Base interface for attack detection modules
    /// </summary>
    public interface IAttackDetectionModule
    {
        string ModuleName { get; }
        Task<AttackDetectionResult?> DetectAsync(HttpContext context);
        void Reset();
    }
}
