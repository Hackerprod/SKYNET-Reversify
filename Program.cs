using Reversify.Modules;
using Reversify.Services;
using Reversify.Middleware;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.WriteIndented = true;
    });

// Registrar HttpClient para el proxy
builder.Services.AddHttpClient("ProxyClient")
    .ConfigureHttpClient(c => { c.Timeout = System.Threading.Timeout.InfiniteTimeSpan; })
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        AutomaticDecompression = System.Net.DecompressionMethods.None
    });

// Registrar servicios de proxy
builder.Services.AddSingleton<IProxyService, ProxyService>();
builder.Services.AddSingleton<HttpsConfigurationService>();
builder.Services.AddHostedService<ProxyConfigurationService>();
builder.Services.AddSingleton<ProxyConfigurationService>(sp =>
    sp.GetServices<IHostedService>().OfType<ProxyConfigurationService>().First());

// Registrar módulos de detección de ataques
builder.Services.AddSingleton<IAttackDetectionModule, DDoSDetectionModule>();

// Variable compartida para acceder al HttpsConfigurationService desde el callback de SNI
HttpsConfigurationService? globalHttpsService = null;

// Configurar Kestrel ANTES de Build()
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ListenAnyIP(80); // HTTP

    serverOptions.ListenAnyIP(443, listenOptions =>
    {
        listenOptions.UseHttps(httpsOptions =>
        {
            // Usar SNI (Server Name Indication) para seleccionar certificado por host
            httpsOptions.ServerCertificateSelector = (connectionContext, name) =>
            {
                // El servicio ya debe estar inicializado en globalHttpsService
                // después de app.Build()

                if (string.IsNullOrEmpty(name))
                {
                    Console.WriteLine("⚠️  SNI: Sin hostname proporcionado");
                    return null;
                }

                if (globalHttpsService == null)
                {
                    Console.WriteLine($"⚠️  SNI: HttpsConfigurationService no disponible todavía para '{name}'");
                    return null;
                }

                var cert = globalHttpsService.GetCertificateForHost(name);

                if (cert == null)
                {
                    Console.WriteLine($"❌ SNI: No se encontró certificado para '{name}'");

                    // Listar hosts disponibles
                    var availableHosts = globalHttpsService.GetConfiguredHosts();
                    if (availableHosts.Any())
                    {
                        Console.WriteLine($"   Hosts disponibles: {string.Join(", ", availableHosts)}");
                    }
                    else
                    {
                        Console.WriteLine($"   No hay certificados cargados todavía");
                    }
                }

                return cert;
            };
        });
    });
});

var app = builder.Build();

// Obtener el servicio HTTPS después del build
globalHttpsService = app.Services.GetRequiredService<HttpsConfigurationService>();
Console.WriteLine("✅ HttpsConfigurationService inicializado");

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// Redirigir HTTP -> HTTPS en el edge para evitar contenido mixto
app.UseHttpsRedirection();

// Ejecutar el proxy inverso antes de archivos estáticos/rutas locales
app.UseReverseProxy();

app.UseStaticFiles();
app.UseRouting();

// Middleware de detección de ataques (TEMPORALMENTE DESHABILITADO)
// app.UseAttackDetection();

app.UseAuthorization();

// ✨ MIDDLEWARE DE PROXY INVERSO PERSONALIZADO ✨
// Este middleware intercepta peticiones basándose en el Host header
// y las redirige al servidor local configurado

// Razor Pages y Controllers (solo se ejecutan si el proxy no interceptó)
app.MapRazorPages();
app.MapControllers();

Console.WriteLine("🚀 Iniciando servidor...");
app.Run();