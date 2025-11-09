using System.Collections.Concurrent;
using System.Text.Json;
using Reversify.Models;

namespace Reversify.Services
{
    /// <summary>
    /// Servicio para gestionar la configuración de proxies desde archivos JSON
    /// </summary>
    public class ProxyConfigurationService : IHostedService, IDisposable
    {
        private readonly ILogger<ProxyConfigurationService> _logger;
        private readonly string _configurationPath;
        private readonly ConcurrentDictionary<string, ProxyConfig> _configurations;
        private FileSystemWatcher? _fileWatcher;
        private readonly Dictionary<string, FileSystemWatcher> _certificateWatchers;
        private readonly IProxyService _proxyService;
        private readonly HttpsConfigurationService _httpsService;

        public ProxyConfigurationService(
            ILogger<ProxyConfigurationService> logger,
            IConfiguration configuration,
            IProxyService proxyService,
            HttpsConfigurationService httpsService)
        {
            _logger = logger;
            _proxyService = proxyService;
            _httpsService = httpsService;
            _configurationPath = configuration["ProxyConfigPath"] ??
                Path.Combine(Directory.GetCurrentDirectory(), "Configurations");
            _configurations = new ConcurrentDictionary<string, ProxyConfig>();
            _certificateWatchers = new Dictionary<string, FileSystemWatcher>();
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Iniciando servicio de configuración de proxies");

            // Crear directorio si no existe
            if (!Directory.Exists(_configurationPath))
            {
                Directory.CreateDirectory(_configurationPath);
                _logger.LogInformation($"Directorio de configuración creado: {_configurationPath}");
            }

            // Cargar configuraciones existentes
            LoadConfigurations();

            // Configurar FileSystemWatcher
            SetupFileWatcher();

            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Deteniendo servicio de configuración de proxies");
            _fileWatcher?.Dispose();
            return Task.CompletedTask;
        }

        private void SetupFileWatcher()
        {
            _fileWatcher = new FileSystemWatcher(_configurationPath)
            {
                Filter = "*.json",
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                EnableRaisingEvents = true
            };

            _fileWatcher.Created += OnConfigurationFileChanged;
            _fileWatcher.Changed += OnConfigurationFileChanged;
            _fileWatcher.Deleted += OnConfigurationFileDeleted;
            _fileWatcher.Renamed += OnConfigurationFileRenamed;

            _logger.LogInformation("FileSystemWatcher configurado correctamente");
        }

        private void OnConfigurationFileChanged(object sender, FileSystemEventArgs e)
        {
            _logger.LogInformation($"Archivo de configuración modificado: {e.Name}");

            // Pequeño delay para asegurar que el archivo está completamente escrito
            Task.Delay(100).ContinueWith(_ => LoadConfiguration(e.FullPath));
        }

        private void OnConfigurationFileDeleted(object sender, FileSystemEventArgs e)
        {
            _logger.LogInformation($"Archivo de configuración eliminado: {e.Name}");

            // Buscar la configuración por nombre de archivo o por ID
            var fileName = Path.GetFileNameWithoutExtension(e.Name);
            
            if (string.IsNullOrEmpty(fileName))
            {
                _logger.LogWarning($"Nombre de archivo inválido: {e.Name}");
                return;
            }
            
            // Intentar remover usando el nombre del archivo como clave
            if (_configurations.TryRemove(fileName, out var config))
            {
                _proxyService.RemoveProxy(config.DnsUrl);
                _logger.LogInformation($"Configuración removida por nombre de archivo: {config.Name}");
                return;
            }
            
            // Si no se encontró por nombre de archivo, buscar por ID que coincida
            var configToRemove = _configurations.Values.FirstOrDefault(c => 
            {
                // Comparar si el archivo que se eliminó corresponde a este ID
                var expectedFileName = $"{c.Id}.json";
                var actualFileName = e.Name;
                return expectedFileName.Equals(actualFileName, StringComparison.OrdinalIgnoreCase);
            });
            
            if (configToRemove != null)
            {
                if (_configurations.TryRemove(configToRemove.Id, out _))
                {
                    _proxyService.RemoveProxy(configToRemove.DnsUrl);
                    _logger.LogInformation($"Configuración removida por ID: {configToRemove.Name} ({configToRemove.Id})");
                }
            }
            else
            {
                _logger.LogWarning($"No se encontró configuración para el archivo eliminado: {e.Name}");
            }
        }

        private void OnConfigurationFileRenamed(object sender, RenamedEventArgs e)
        {
            _logger.LogInformation($"Archivo de configuración renombrado: {e.OldName} -> {e.Name}");

            // Remover la configuración antigua
            var oldFileName = Path.GetFileNameWithoutExtension(e.OldName);
            if (!string.IsNullOrEmpty(oldFileName) && _configurations.TryRemove(oldFileName, out var oldConfig))
            {
                _proxyService.RemoveProxy(oldConfig.DnsUrl);
            }

            // Cargar la nueva configuración
            LoadConfiguration(e.FullPath);
        }

        private void LoadConfigurations()
        {
            var jsonFiles = Directory.GetFiles(_configurationPath, "*.json");
            _logger.LogInformation($"Cargando {jsonFiles.Length} archivos de configuración");

            foreach (var file in jsonFiles)
            {
                LoadConfiguration(file);
            }
        }

        private void LoadConfiguration(string filePath)
        {
            try
            {
                var json = File.ReadAllText(filePath);
                var config = JsonSerializer.Deserialize<ProxyConfig>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (config != null)
                {
                    // Usar el ID del config como clave (debe coincidir con el nombre del archivo)
                    _configurations.AddOrUpdate(config.Id, config, (key, old) => config);

                    // Solo actualizar el servicio de proxy si está activa
                    if (config.Enabled)
                    {
                        _proxyService.AddOrUpdateProxy(config);

                        // Cargar certificado si está configurado un directorio
                        if (!string.IsNullOrEmpty(config.CertificatesDirectory))
                        {
                            _httpsService.AddOrUpdateCertificateFromDirectory(
                                config.DnsUrl,
                                config.CertificatesDirectory,
                                config.CertificatePassword);

                            // Configurar FileSystemWatcher para el directorio de certificados
                            SetupCertificateWatcher(config);
                        }

                        _logger.LogInformation($"Configuración cargada y activada: {config.Name} ({config.DnsUrl} -> {config.LocalUrl})");
                    }
                    else
                    {
                        // Si está desactivada, asegurar que no esté en el proxy
                        _proxyService.RemoveProxy(config.DnsUrl);
                        _httpsService.RemoveCertificate(config.DnsUrl);
                        _logger.LogInformation($"Configuración cargada (inactiva): {config.Name}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error al cargar configuración desde {filePath}");
            }
        }

        public IEnumerable<ProxyConfig> GetAllConfigurations()
        {
            return _configurations.Values;
        }

        public ProxyConfig? GetConfiguration(string id)
        {
            _configurations.TryGetValue(id, out var config);
            return config;
        }

        public async Task<bool> SaveConfiguration(ProxyConfig config)
        {
            try
            {
                // Deshabilitar temporalmente el FileSystemWatcher para evitar evento duplicado
                if (_fileWatcher != null)
                {
                    _fileWatcher.EnableRaisingEvents = false;
                }

                var fileName = $"{config.Id}.json";
                var filePath = Path.Combine(_configurationPath, fileName);

                var json = JsonSerializer.Serialize(config, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                await File.WriteAllTextAsync(filePath, json);

                // Actualizar siempre en memoria (independiente de si está habilitada o no)
                _configurations.AddOrUpdate(config.Id, config, (key, old) => config);

                // Solo actualizar el servicio de proxy según el estado
                if (config.Enabled)
                {
                    _proxyService.AddOrUpdateProxy(config);
                    _logger.LogInformation($"Configuración guardada y aplicada: {config.Name} ({config.DnsUrl} -> {config.LocalUrl})");
                }
                else
                {
                    _proxyService.RemoveProxy(config.DnsUrl);
                    _logger.LogInformation($"Configuración guardada como deshabilitada: {config.Name}");
                }

                // Reactivar el FileSystemWatcher después de un pequeño delay
                if (_fileWatcher != null)
                {
                    await Task.Delay(500); // Esperar 500ms para que el archivo termine de escribirse
                    _fileWatcher.EnableRaisingEvents = true;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error al guardar configuración {config.Name}");

                // Asegurar que el FileSystemWatcher se reactive
                if (_fileWatcher != null)
                {
                    _fileWatcher.EnableRaisingEvents = true;
                }

                return false;
            }
        }

        public async Task<bool> DeleteConfiguration(string id)
        {
            try
            {
                _logger.LogInformation($"Intentando eliminar configuración: {id}");
                
                // Deshabilitar temporalmente el FileSystemWatcher
                if (_fileWatcher != null)
                {
                    _fileWatcher.EnableRaisingEvents = false;
                    _logger.LogInformation("FileSystemWatcher deshabilitado");
                }

                // Obtener la configuración antes de eliminarla
                var config = _configurations.Values.FirstOrDefault(c => c.Id == id);

                // Intentar primero con el nombre basado en el ID
                var fileName = $"{id}.json";
                var filePath = Path.Combine(_configurationPath, fileName);
                
                _logger.LogInformation($"Buscando archivo: {filePath}");
                
                // Si no existe, buscar en todos los archivos JSON
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning($"Archivo no encontrado con nombre {fileName}, buscando por ID en todos los archivos...");
                    
                    var allFiles = Directory.GetFiles(_configurationPath, "*.json");
                    foreach (var file in allFiles)
                    {
                        try
                        {
                            var json = await File.ReadAllTextAsync(file);
                            var tempConfig = JsonSerializer.Deserialize<ProxyConfig>(json);
                            if (tempConfig?.Id == id)
                            {
                                filePath = file;
                                _logger.LogInformation($"Archivo encontrado: {filePath}");
                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, $"Error al leer archivo {file}");
                        }
                    }
                }
                
                _logger.LogInformation($"Ruta del archivo a eliminar: {filePath}");
                _logger.LogInformation($"¿Archivo existe?: {File.Exists(filePath)}");

                if (File.Exists(filePath))
                {
                    try
                    {
                        File.Delete(filePath);
                        _logger.LogInformation($"Archivo eliminado: {filePath}");
                    }
                    catch (IOException ioEx)
                    {
                        _logger.LogError(ioEx, $"Error de IO al eliminar archivo: {filePath}");
                        throw new Exception($"El archivo está en uso o bloqueado: {ioEx.Message}", ioEx);
                    }
                    catch (UnauthorizedAccessException uaEx)
                    {
                        _logger.LogError(uaEx, $"Sin permisos para eliminar: {filePath}");
                        throw new Exception($"Sin permisos para eliminar el archivo: {uaEx.Message}", uaEx);
                    }

                    // Remover de memoria inmediatamente
                    if (config != null)
                    {
                        _configurations.TryRemove(id, out _);
                        _proxyService.RemoveProxy(config.DnsUrl);
                        _logger.LogInformation($"Configuración eliminada de memoria: {config.Name} ({id})");
                    }
                    else
                    {
                        _logger.LogInformation($"Configuración eliminada: {id}");
                    }

                    // Reactivar el FileSystemWatcher
                    if (_fileWatcher != null)
                    {
                        await Task.Delay(500);
                        _fileWatcher.EnableRaisingEvents = true;
                        _logger.LogInformation("FileSystemWatcher reactivado");
                    }

                    return true;
                }

                // Reactivar el FileSystemWatcher si no se encontró el archivo
                if (_fileWatcher != null)
                {
                    _fileWatcher.EnableRaisingEvents = true;
                }

                _logger.LogWarning($"Archivo no encontrado para configuración: {id}");
                throw new Exception($"No se encontró el archivo de configuración para el ID: {id}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error al eliminar configuración {id}");

                // Asegurar que el FileSystemWatcher se reactive
                if (_fileWatcher != null)
                {
                    _fileWatcher.EnableRaisingEvents = true;
                }

                throw; // Re-lanzar la excepción para que el controlador la maneje
            }
        }

        private void SetupCertificateWatcher(ProxyConfig config)
        {
            if (string.IsNullOrEmpty(config.CertificatesDirectory) || !Directory.Exists(config.CertificatesDirectory))
                return;

            // Si ya existe un watcher para este directorio, no crear otro
            if (_certificateWatchers.ContainsKey(config.CertificatesDirectory))
                return;

            try
            {
                var watcher = new FileSystemWatcher(config.CertificatesDirectory)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    EnableRaisingEvents = true
                };

                // Configurar filtros para archivos de certificados
                watcher.Filter = "*.*";

                // Eventos
                watcher.Changed += (s, e) => OnCertificateFileChanged(e, config);
                watcher.Created += (s, e) => OnCertificateFileChanged(e, config);
                watcher.Deleted += (s, e) => OnCertificateFileChanged(e, config);

                _certificateWatchers[config.CertificatesDirectory] = watcher;

                _logger.LogInformation($"👁️  Vigilando cambios en certificados: {config.CertificatesDirectory}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error al configurar watcher para certificados: {config.CertificatesDirectory}");
            }
        }

        private void OnCertificateFileChanged(FileSystemEventArgs e, ProxyConfig config)
        {
            // Solo reaccionar a archivos de certificados
            var extension = Path.GetExtension(e.Name ?? "").ToLowerInvariant();
            if (extension != ".crt" && extension != ".key" && extension != ".pfx" && extension != ".p12")
                return;

            _logger.LogInformation($"🔄 Certificado modificado: {e.Name} ({e.ChangeType})");

            // Pequeño delay para asegurar que el archivo está completamente escrito
            Task.Delay(500).ContinueWith(_ =>
            {
                _logger.LogInformation($"🔄 Recargando certificado para: {config.DnsUrl}");

                _httpsService.AddOrUpdateCertificateFromDirectory(
                    config.DnsUrl,
                    config.CertificatesDirectory,
                    config.CertificatePassword);
            });
        }

        public void Dispose()
        {
            _fileWatcher?.Dispose();

            foreach (var watcher in _certificateWatchers.Values)
            {
                watcher?.Dispose();
            }

            _certificateWatchers.Clear();
        }
    }
}
