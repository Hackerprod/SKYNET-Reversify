# SKYNET Reversify (ProxInv)

Dynamic reverse proxy for .NET 8 with per‑host TLS (SNI), JSON‑based configuration, and optional DDoS detection. Runs on Kestrel listening on ports 80/443.

## Features
- Host‑based routing: map `dnsUrl` → local service (`localUrl`).
- Hot‑reload configuration: watches `Configurations/*.json` for changes.
- Per‑host certificates: auto‑select via SNI; supports `.pfx` or `.crt/.key`.
- Forwarded headers: sends X‑Forwarded‑For/Proto/Host/Port to backends.
- Optional DDoS module: rate heuristics with temporary IP blocking.

## Quick Start
Prereqs: .NET 8 SDK, open ports 80/443 (administrator privileges may be required on Windows).

```bash
dotnet restore
dotnet run --project ProxInv.csproj
# or with hot reload
dotnet watch run
# Windows helpers
WATCH.cmd   # hot reload
RUN.cmd     # run
```

## Configuration
appsettings.json (defaults shown):
```json
{
  "ProxyConfigPath": "Configurations",
  "DDoS": {
    "MaxRequestsPerMinute": 100,
    "MaxRequestsPerSecond": 10,
    "TimeWindowMinutes": 5,
    "BlockDurationMinutes": 30
  }
}
```

Create JSON files in `Configurations/` (case‑insensitive property names):
```json
{
  "id": "example-001",
  "name": "My App",
  "dnsUrl": "www.example.com",
  "localUrl": "http://127.0.0.1:3000",
  "certificatesDirectory": "C:\\Certs",   
  "certificatePassword": null,
  "enabled": true
}
```
Notes:
- Certificates directory: files must match the host (CN/SAN). The app loads `.pfx` or `.crt/.key` pairs and also registers the `www.` alias when covered by the cert.
- Changing JSON or certificate files is picked up automatically.

## API
Manage proxy configs via REST:
- GET `/api/ProxyConfig` — list configs
- GET `/api/ProxyConfig/{id}` — get by ID
- POST `/api/ProxyConfig` — create (server assigns `id` if missing)
- PUT `/api/ProxyConfig/{id}` — update
- DELETE `/api/ProxyConfig/{id}` — delete

## Architecture
- Entry: `Program.cs` configures Kestrel (80/443) and SNI certificate selection.
- Middleware: `Middleware/ReverseProxyMiddleware.cs` forwards requests and headers.
- Services: `Services/*` load configs, manage proxies, and TLS certificates.
- Modules: `Modules/*` provide attack detection (`DDoSDetectionModule`) and middleware (`AttackDetectionMiddleware`).

## Production
```bash
dotnet publish -c Release -o out
./out/ProxInv.exe
```
Harden ports, don’t commit secrets, and validate backend targets when modifying middleware/modules.

