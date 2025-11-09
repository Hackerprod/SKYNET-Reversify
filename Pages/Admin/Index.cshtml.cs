using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Reversify.Models;
using Reversify.Services;

namespace Reversify.Pages.Admin
{
    public class IndexModel : PageModel
    {
        private readonly ProxyConfigurationService _configService;
        private readonly IConfiguration _configuration;

        public IndexModel(ProxyConfigurationService configService, IConfiguration configuration)
        {
            _configService = configService;
            _configuration = configuration;
        }

        public List<ProxyConfig> Configurations { get; set; } = new();
        public string ConfigurationPath { get; set; } = string.Empty;

        public void OnGet()
        {
            Configurations = _configService.GetAllConfigurations().ToList();
            ConfigurationPath = _configuration["ProxyConfigPath"] ??
                Path.Combine(Directory.GetCurrentDirectory(), "Configurations");
        }

        public async Task<IActionResult> OnPostDeleteAsync(string id)
        {
            await _configService.DeleteConfiguration(id);
            return RedirectToPage();
        }
    }
}
