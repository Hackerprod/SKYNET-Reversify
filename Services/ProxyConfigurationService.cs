using System.Collections.Concurrent;
using System.Text.Json;
using Reversify.Models;

namespace Reversify.Services
{
    /// <summary>
    /// Service to manage proxy configuration from JSON files
    /// </summary>
    public class ProxyConfigurationService : IHostedService, IDisposable
    {
        private readonly string _configurationPath;
        private readonly ConcurrentDictionary<string, ProxyConfig> _configurations;
        private FileSystemWatcher? _fileWatcher;
        private readonly Dictionary<string, FileSystemWatcher> _certificateWatchers;
        private readonly IProxyService _proxyService;
        private readonly HttpsConfigurationService _httpsService;

        public ProxyConfigurationService(
            IConfiguration configuration,
            IProxyService proxyService,
            HttpsConfigurationService httpsService)
        {
            _proxyService = proxyService;
            _httpsService = httpsService;
            _configurationPath = configuration["ProxyConfigPath"] ??
                Path.Combine(Directory.GetCurrentDirectory(), "Configurations");
            _configurations = new ConcurrentDictionary<string, ProxyConfig>();
            _certificateWatchers = new Dictionary<string, FileSystemWatcher>();
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            Log.Info("Starting proxy configuration service");

            // Create directory if it does not exist
            if (!Directory.Exists(_configurationPath))
            {
                Directory.CreateDirectory(_configurationPath);
                Log.Info($"Configuration directory created: {_configurationPath}");
            }

            // Load existing configurations
            LoadConfigurations();

            // Configure FileSystemWatcher
            SetupFileWatcher();

            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            Log.Info("Stopping proxy configuration service");
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
        }

        private void OnConfigurationFileChanged(object sender, FileSystemEventArgs e)
        {
            Log.Info($"Configuration file changed: {e.Name}");

            // Small delay to ensure the file is fully written
            Task.Delay(100).ContinueWith(_ => LoadConfiguration(e.FullPath));
        }

        private void OnConfigurationFileDeleted(object sender, FileSystemEventArgs e)
        {
            Log.Info($"Configuration file deleted: {e.Name}");

            // Find configuration by file name or by ID
            var fileName = Path.GetFileNameWithoutExtension(e.Name);

            if (string.IsNullOrEmpty(fileName))
            {
                Log.Warn($"Invalid file name: {e.Name}");
                return;
            }

            // Try removing using the file name as the key
            if (_configurations.TryRemove(fileName, out var config))
            {
                _proxyService.RemoveProxy(config.DnsUrl);
                Log.Info($"Configuration removed by file name: {config.Name}");
                return;
            }

            // If not found by file name, look for matching ID
            var configToRemove = _configurations.Values.FirstOrDefault(c =>
            {
                // Compare if the deleted file corresponds to this ID
                var expectedFileName = $"{c.Id}.json";
                var actualFileName = e.Name;
                return expectedFileName.Equals(actualFileName, StringComparison.OrdinalIgnoreCase);
            });

            if (configToRemove != null)
            {
                if (_configurations.TryRemove(configToRemove.Id, out _))
                {
                    _proxyService.RemoveProxy(configToRemove.DnsUrl);
                    Log.Info($"Configuration removed by ID: {configToRemove.Name} ({configToRemove.Id})");
                }
            }
            else
            {
                Log.Warn($"No configuration found for deleted file: {e.Name}");
            }
        }

        private void OnConfigurationFileRenamed(object sender, RenamedEventArgs e)
        {
            Log.Info($"Configuration file renamed: {e.OldName} -> {e.Name}");

            // Remove old configuration
            var oldFileName = Path.GetFileNameWithoutExtension(e.OldName);
            if (!string.IsNullOrEmpty(oldFileName) && _configurations.TryRemove(oldFileName, out var oldConfig))
            {
                _proxyService.RemoveProxy(oldConfig.DnsUrl);
            }

            // Load the new configuration
            LoadConfiguration(e.FullPath);
        }

        private void LoadConfigurations()
        {
            var jsonFiles = Directory.GetFiles(_configurationPath, "*.json");
            Log.Info($"Loading {jsonFiles.Length} configuration files");

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
                    // Use the config ID as the key (should match the file name)
                    _configurations.AddOrUpdate(config.Id, config, (key, old) => config);

                    // Only update proxy service if enabled
                    if (config.Enabled)
                    {
                        _proxyService.AddOrUpdateProxy(config);

                        // Load certificate if a directory is configured
                        if (!string.IsNullOrEmpty(config.CertificatesDirectory))
                        {
                            _httpsService.AddOrUpdateCertificateFromDirectory(
                                config.DnsUrl,
                                config.CertificatesDirectory,
                                config.CertificatePassword);

                            // Configure FileSystemWatcher for certificate directory
                            SetupCertificateWatcher(config);
                        }

                        Log.Info($"Configuration loaded and activated: {config.Name} ({config.DnsUrl} -> {config.LocalUrl})");
                    }
                    else
                    {
                        // If disabled, ensure it is not in the proxy
                        _proxyService.RemoveProxy(config.DnsUrl);
                        _httpsService.RemoveCertificate(config.DnsUrl);
                        Log.Info($"Configuration loaded (inactive): {config.Name}");
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Error loading configuration from {filePath}: {ex.Message}");
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
                // Temporarily disable FileSystemWatcher to avoid duplicate events
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

                // Always update in memory (regardless of enabled status)
                _configurations.AddOrUpdate(config.Id, config, (key, old) => config);

                // Update proxy service based on status
                if (config.Enabled)
                {
                    _proxyService.AddOrUpdateProxy(config);
                    Log.Info($"Configuration saved and applied: {config.Name} ({config.DnsUrl} -> {config.LocalUrl})");
                }
                else
                {
                    _proxyService.RemoveProxy(config.DnsUrl);
                    Log.Info($"Configuration saved as disabled: {config.Name}");
                }

                // Re-enable FileSystemWatcher after a short delay
                if (_fileWatcher != null)
                {
                    await Task.Delay(500);
                    _fileWatcher.EnableRaisingEvents = true;
                }

                return true;
            }
            catch (Exception ex)
            {
                Log.Error($"Error saving configuration {config.Name}: {ex.Message}");

                // Ensure FileSystemWatcher is re-enabled
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
                Log.Info($"Attempting to delete configuration: {id}");

                // Temporarily disable FileSystemWatcher
                if (_fileWatcher != null)
                {
                    _fileWatcher.EnableRaisingEvents = false;
                }

                // Get configuration before deleting
                var config = _configurations.Values.FirstOrDefault(c => c.Id == id);

                // Try first with the ID-based file name
                var fileName = $"{id}.json";
                var filePath = Path.Combine(_configurationPath, fileName);

                // If not found, search all JSON files
                if (!File.Exists(filePath))
                {
                    Log.Warn($"File not found with name {fileName}, searching by ID in all files...");

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
                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.Warn($"Error reading file {file}: {ex.Message}");
                        }
                    }
                }

                if (File.Exists(filePath))
                {
                    try
                    {
                        File.Delete(filePath);
                    }
                    catch (IOException ioEx)
                    {
                        Log.Error($"IO error deleting file: {filePath}. {ioEx.Message}");
                        throw new Exception($"File is in use or locked: {ioEx.Message}", ioEx);
                    }
                    catch (UnauthorizedAccessException uaEx)
                    {
                        Log.Error($"No permission to delete file: {filePath}. {uaEx.Message}");
                        throw new Exception($"No permission to delete file: {uaEx.Message}", uaEx);
                    }

                    // Remove from memory immediately
                    if (config != null)
                    {
                        _configurations.TryRemove(id, out _);
                        _proxyService.RemoveProxy(config.DnsUrl);
                        Log.Info($"Configuration deleted: {config.Name} ({id})");
                    }
                    else
                    {
                        Log.Info($"Configuration deleted: {id}");
                    }

                    // Re-enable FileSystemWatcher
                    if (_fileWatcher != null)
                    {
                        await Task.Delay(500);
                        _fileWatcher.EnableRaisingEvents = true;
                    }

                    return true;
                }

                // Re-enable FileSystemWatcher if file not found
                if (_fileWatcher != null)
                {
                    _fileWatcher.EnableRaisingEvents = true;
                }

                Log.Warn($"File not found for configuration: {id}");
                throw new Exception($"Configuration file not found for ID: {id}");
            }
            catch (Exception ex)
            {
                Log.Error($"Error deleting configuration {id}: {ex.Message}");

                // Ensure FileSystemWatcher is re-enabled
                if (_fileWatcher != null)
                {
                    _fileWatcher.EnableRaisingEvents = true;
                }

                throw;
            }
        }

        private void SetupCertificateWatcher(ProxyConfig config)
        {
            if (string.IsNullOrEmpty(config.CertificatesDirectory) || !Directory.Exists(config.CertificatesDirectory))
                return;

            // If a watcher already exists for this directory, do not create another
            if (_certificateWatchers.ContainsKey(config.CertificatesDirectory))
                return;

            try
            {
                var watcher = new FileSystemWatcher(config.CertificatesDirectory)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    EnableRaisingEvents = true
                };

                // Watch all certificate files
                watcher.Filter = "*.*";

                // Events
                watcher.Changed += (s, e) => OnCertificateFileChanged(e, config);
                watcher.Created += (s, e) => OnCertificateFileChanged(e, config);
                watcher.Deleted += (s, e) => OnCertificateFileChanged(e, config);

                _certificateWatchers[config.CertificatesDirectory] = watcher;

                Log.Info($"Watching certificate changes: {config.CertificatesDirectory}");
            }
            catch (Exception ex)
            {
                Log.Error($"Error configuring watcher for certificates: {config.CertificatesDirectory}. {ex.Message}");
            }
        }

        private void OnCertificateFileChanged(FileSystemEventArgs e, ProxyConfig config)
        {
            // Only react to certificate files
            var extension = Path.GetExtension(e.Name ?? "").ToLowerInvariant();
            if (extension != ".crt" && extension != ".key" && extension != ".pfx" && extension != ".p12")
                return;

            Log.Info($"Certificate changed: {e.Name} ({e.ChangeType})");

            // Small delay to ensure the file is fully written
            Task.Delay(500).ContinueWith(_ =>
            {
                Log.Info($"Reloading certificate for: {config.DnsUrl}");

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
