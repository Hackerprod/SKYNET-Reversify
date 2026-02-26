using Reversify.Modules;
using Reversify.Services;
using Reversify.Middleware;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddJsonFile("appsettings.local.json", optional: true, reloadOnChange: true);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.WriteIndented = true;
    });

// Auth (cookie) for simple dashboard access
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/";
        options.AccessDeniedPath = "/";
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
    });
builder.Services.AddAuthorization();

// Register HttpClient for the proxy
builder.Services.AddHttpClient("ProxyClient")
    .ConfigureHttpClient(c => { c.Timeout = System.Threading.Timeout.InfiniteTimeSpan; })
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        AutomaticDecompression = System.Net.DecompressionMethods.None
    });

// Register proxy services
builder.Services.AddSingleton<IProxyService, ProxyService>();
builder.Services.AddSingleton<HttpsConfigurationService>();
builder.Services.AddHostedService<ProxyConfigurationService>();
builder.Services.AddSingleton<ProxyConfigurationService>(sp =>
    sp.GetServices<IHostedService>().OfType<ProxyConfigurationService>().First());

// Register attack detection modules
builder.Services.AddSingleton<IAttackDetectionModule, DDoSDetectionModule>();

// Shared variable to access HttpsConfigurationService from the SNI callback
HttpsConfigurationService? globalHttpsService = null;

// Configure Kestrel BEFORE Build()
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ListenAnyIP(80); // HTTP

    serverOptions.ListenAnyIP(443, listenOptions =>
    {
        listenOptions.UseHttps(httpsOptions =>
        {
            // Use SNI (Server Name Indication) to select certificate per host
            httpsOptions.ServerCertificateSelector = (connectionContext, name) =>
            {
                // Service should already be initialized in globalHttpsService
                // after app.Build()

                if (string.IsNullOrEmpty(name))
                {
                    Log.Warn("SNI: no hostname provided");
                    return null;
                }

                if (globalHttpsService == null)
                {
                    Log.Warn($"SNI: HttpsConfigurationService not available yet for '{name}'");
                    return null;
                }

                var cert = globalHttpsService.GetCertificateForHost(name);

                if (cert == null)
                {
                    Log.Warn($"SNI: no certificate found for '{name}'");

                    // List available hosts
                    var availableHosts = globalHttpsService.GetConfiguredHosts();
                    if (availableHosts.Any())
                    {
                        Log.Info($"Available hosts: {string.Join(", ", availableHosts)}");
                    }
                    else
                    {
                        Log.Info("No certificates loaded yet");
                    }
                }

                return cert;
            };
        });
    });
});

var app = builder.Build();

// Get HTTPS service after build
globalHttpsService = app.Services.GetRequiredService<HttpsConfigurationService>();
Log.Info("HttpsConfigurationService initialized");

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// Redirect HTTP -> HTTPS at the edge to avoid mixed content
app.UseHttpsRedirection();

// Run reverse proxy before static files/local routes
app.UseReverseProxy();

app.UseStaticFiles();
app.UseRouting();

// Attack detection middleware (TEMPORARILY DISABLED)
// app.UseAttackDetection();

app.UseAuthentication();
app.UseAuthorization();

// Custom reverse proxy middleware
// This middleware intercepts requests based on the Host header
// and forwards them to the configured local server

// Razor Pages and Controllers (only run if the proxy did not intercept)
app.MapRazorPages();
app.MapControllers();

Log.Info("Starting server...");
app.Run();
