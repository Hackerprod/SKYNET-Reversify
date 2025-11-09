using Microsoft.AspNetCore.Mvc;
using Reversify.Models;
using Reversify.Services;

namespace Reversify.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProxyConfigController : ControllerBase
    {
        private readonly ProxyConfigurationService _configService;
        private readonly ILogger<ProxyConfigController> _logger;

        public ProxyConfigController(
            ProxyConfigurationService configService,
            ILogger<ProxyConfigController> logger)
        {
            _configService = configService;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult GetAll()
        {
            var configs = _configService.GetAllConfigurations();
            return Ok(configs);
        }

        [HttpGet("{id}")]
        public IActionResult GetById(string id)
        {
            var config = _configService.GetConfiguration(id);
            if (config == null)
            {
                return NotFound(new { message = "Configuración no encontrada" });
            }

            return Ok(config);
        }

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] ProxyConfig config)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            config.Id = Guid.NewGuid().ToString();
            var result = await _configService.SaveConfiguration(config);

            if (result)
            {
                _logger.LogInformation($"Configuración creada: {config.Name}");
                return CreatedAtAction(nameof(GetById), new { id = config.Id }, config);
            }

            return StatusCode(500, new { message = "Error al guardar la configuración" });
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> Update(string id, [FromBody] ProxyConfig config)
        {
            if (id != config.Id)
            {
                return BadRequest(new { message = "El ID no coincide" });
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var existingConfig = _configService.GetConfiguration(id);
            if (existingConfig == null)
            {
                return NotFound(new { message = "Configuración no encontrada" });
            }

            var result = await _configService.SaveConfiguration(config);

            if (result)
            {
                _logger.LogInformation($"Configuración actualizada: {config.Name}");
                return Ok(config);
            }

            return StatusCode(500, new { message = "Error al actualizar la configuración" });
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(string id)
        {
            try
            {
                var existingConfig = _configService.GetConfiguration(id);
                if (existingConfig == null)
                {
                    return NotFound(new { message = "Configuración no encontrada" });
                }

                var result = await _configService.DeleteConfiguration(id);

                if (result)
                {
                    _logger.LogInformation($"Configuración eliminada: {id}");
                    return Ok(new { message = "Configuración eliminada correctamente" });
                }

                return StatusCode(500, new { message = "Error al eliminar la configuración. El archivo puede estar en uso." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error al eliminar configuración {id}");
                return StatusCode(500, new { message = $"Error: {ex.Message}" });
            }
        }
    }
}
