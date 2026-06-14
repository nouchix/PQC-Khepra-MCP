# Khepra API Server

Production-ready REST + WebSocket API server for the AdinKhepra Protocol.

## Features

- **REST API**: Complete HTTP endpoints for scans, DAG, STIG, ERT, and license management
- **WebSocket**: Real-time updates for scan progress, DAG changes, and license events
- **Authentication**: API key-based authentication with machine ID validation
- **TLS Support**: Automatic Let's Encrypt certificate management for production
- **Rate Limiting**: Built-in rate limiting to prevent abuse
- **CORS**: Configurable CORS headers for web dashboard integration
- **Graceful Shutdown**: Proper cleanup of resources on termination

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Khepra API Server                        │
│                                                              │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────┐ │
│  │   REST API     │  │   WebSocket    │  │ Auth Middleware│ │
│  │  (Port 8080)   │  │    Hub         │  │               │ │
│  └────────┬───────┘  └────────┬───────┘  └──────┬───────┘ │
│           │                   │                  │          │
│           └───────────────────┴──────────────────┘          │
│                            │                                 │
│           ┌────────────────┴────────────────┐               │
│           │                                  │               │
│  ┌────────▼─────────┐            ┌──────────▼──────────┐   │
│  │  DAG Store       │            │  License Manager     │   │
│  │  (Persistent)    │            │  (Cloudflare)        │   │
│  └──────────────────┘            └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                        │
                        ▼
         ┌──────────────────────────┐
         │  SouHimBou.ai Dashboard  │
         │  (React + WebSocket)     │
         └──────────────────────────┘
```

## API Endpoints

### Public Endpoints

| Method | Endpoint         | Description            |
|--------|------------------|------------------------|
| GET    | `/health`        | Health check           |
| GET    | `/version`       | Server version         |

### Authenticated Endpoints (Require `Authorization: Bearer <api_key>`)

#### Scans

| Method | Endpoint                  | Description                |
|--------|---------------------------|----------------------------|
| POST   | `/api/v1/scans/trigger`   | Trigger new scan           |
| GET    | `/api/v1/scans/:id`       | Get scan status            |
| GET    | `/api/v1/scans`           | List all scans (paginated) |

#### DAG (Living Trust Constellation)

| Method | Endpoint                  | Description                |
|--------|---------------------------|----------------------------|
| GET    | `/api/v1/dag/nodes`       | Get all DAG nodes          |
| GET    | `/api/v1/dag/nodes/:id`   | Get specific node          |

#### STIG Validation

| Method | Endpoint                  | Description                |
|--------|---------------------------|----------------------------|
| POST   | `/api/v1/stig/validate`   | Validate STIG compliance   |

#### ERT (Evidence Recording Token)

| Method | Endpoint                  | Description                |
|--------|---------------------------|----------------------------|
| POST   | `/api/v1/ert/generate`    | Generate ERT               |
| GET    | `/api/v1/ert/verify/:id`  | Verify ERT signature       |

#### License

| Method | Endpoint                  | Description                |
|--------|---------------------------|----------------------------|
| GET    | `/api/v1/license/status`  | Get license status         |

### WebSocket Endpoints

| Endpoint           | Description                          |
|--------------------|--------------------------------------|
| `/ws/scans`        | Real-time scan updates               |
| `/ws/dag`          | Real-time DAG node updates           |
| `/ws/license`      | Real-time license status updates     |

## Usage

### Basic Setup

```go
package main

import (
    "log"
    "github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/apiserver"
    "github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
    "github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
)

func main() {
    // Initialize DAG (global singleton)
    dagStore := dag.GlobalDAG()

    // Initialize license manager
    licMgr, err := license.NewManager("https://telemetry.souhimbou.org")
    if err != nil {
        log.Fatalf("Failed to create license manager: %v", err)
    }

    if err := licMgr.Initialize(); err != nil {
        log.Printf("License validation failed: %v", err)
    }

    // Create API server
    config := &apiserver.Config{
        Host:       "0.0.0.0",
        Port:       8080,
        TLSEnabled: false,
        Debug:      false,
    }

    // Create adapters
    dagAdapter := apiserver.NewDAGStoreAdapter(dagStore)
    licAdapter := apiserver.NewLicenseManagerAdapter(licMgr)

    // Start server
    server := apiserver.NewServer(config, dagAdapter, licAdapter)

    if err := server.Start(); err != nil {
        log.Fatalf("Server error: %v", err)
    }
}
```

### Production Setup (with TLS)

```go
config := &apiserver.Config{
    Host:         "0.0.0.0",
    Port:         443,
    TLSEnabled:   true,
    TLSDomain:    "khepra.example.com",
    CertCacheDir: "/var/cache/khepra-certs",
    Debug:        false,
}
```

### API Request Examples

#### Trigger Scan

```bash
curl -X POST http://localhost:8080/api/v1/scans/trigger \
  -H "Authorization: Bearer <machine_id>" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "scan_type": "crypto",
    "priority": 5
  }'
```

**Response:**
```json
{
  "scan_id": "a3d4e5f6-1234-5678-9abc-def012345678",
  "status": "queued",
  "target_url": "https://example.com",
  "scan_type": "crypto",
  "queued_at": "2026-01-16T10:30:00Z",
  "estimated_completion": "2026-01-16T10:35:00Z",
  "websocket_url": "wss://localhost:8080/ws/scans"
}
```

#### Get Scan Status

```bash
curl http://localhost:8080/api/v1/scans/a3d4e5f6-1234-5678-9abc-def012345678 \
  -H "Authorization: Bearer <machine_id>"
```

**Response:**
```json
{
  "scan_id": "a3d4e5f6-1234-5678-9abc-def012345678",
  "status": "completed",
  "progress": 1.0,
  "results": {
    "vulnerabilities_found": 3,
    "crypto_issues": 1,
    "stig_violations": 2
  }
}
```

#### STIG Validation

```bash
curl -X POST http://localhost:8080/api/v1/stig/validate \
  -H "Authorization: Bearer <machine_id>" \
  -H "Content-Type: application/json" \
  -d '{
    "stig_version": "RHEL9",
    "target_host": "192.168.1.100"
  }'
```

**Response:**
```json
{
  "validation_id": "val-12345",
  "stig_version": "RHEL9",
  "target_host": "192.168.1.100",
  "total_checks": 100,
  "passed": 85,
  "failed": 15,
  "not_applicable": 0,
  "score": 85.0,
  "results": [...]
}
```

### WebSocket Client Example (JavaScript)

```javascript
const ws = new WebSocket('wss://khepra.example.com/ws/scans');

ws.onopen = () => {
    console.log('Connected to Khepra scan updates');
};

ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    console.log('Scan update:', message);

    if (message.type === 'scan_update') {
        // Update UI with scan progress
        updateScanProgress(message.data);
    }
};

ws.onerror = (error) => {
    console.error('WebSocket error:', error);
};

ws.onclose = () => {
    console.log('Disconnected from Khepra');
    // Implement reconnection logic
    setTimeout(() => reconnect(), 5000);
};
```

## Configuration

| Field           | Type     | Description                              | Default         |
|-----------------|----------|------------------------------------------|-----------------|
| `Host`          | string   | Listen address                           | `"0.0.0.0"`     |
| `Port`          | int      | Listen port                              | `8080`          |
| `TLSEnabled`    | bool     | Enable Let's Encrypt TLS                 | `false`         |
| `TLSDomain`     | string   | Domain for Let's Encrypt                 | `""`            |
| `CertCacheDir`  | string   | Certificate cache directory              | `""`            |
| `AllowedOrigins`| []string | CORS allowed origins                     | `["*"]`         |
| `Debug`         | bool     | Enable debug logging                     | `false`         |

## Integration with SouHimBou.ai

The API server is designed to integrate seamlessly with the SouHimBou.ai React dashboard:

```typescript
// src/hooks/useKhepraWebSocket.ts
import { useEffect, useState } from 'react';

export function useKhepraWebSocket(deploymentURL: string) {
  const [scanUpdates, setScanUpdates] = useState([]);

  useEffect(() => {
    const ws = new WebSocket(`wss://${deploymentURL}/ws/scans`);

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'scan_update') {
        setScanUpdates(prev => [...prev, message.data]);
      }
    };

    return () => ws.close();
  }, [deploymentURL]);

  return scanUpdates;
}
```

## Security

- **Authentication**: All endpoints (except `/health` and `/version`) require `Authorization: Bearer <api_key>`
- **Rate Limiting**: 100 requests per minute per IP
- **TLS**: Automatic Let's Encrypt certificate management in production
- **CORS**: Configurable allowed origins
- **Input Validation**: All request bodies are validated using Gin's binding

## Deployment

### Development

```bash
go run cmd/agent/main.go
```

### Production (Systemd)

```ini
[Unit]
Description=Khepra API Server
After=network.target

[Service]
Type=simple
User=khepra
WorkingDirectory=/opt/khepra
ExecStart=/opt/khepra/adinkhepra-agent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Docker

```dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o khepra-agent cmd/agent/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/khepra-agent .
EXPOSE 8080
CMD ["./khepra-agent"]
```

## Monitoring

The API server exposes a `/health` endpoint for monitoring:

```bash
curl http://localhost:8080/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 3600.5,
  "dag_nodes": 1234,
  "license_status": "valid",
  "components": {
    "dag_store": "healthy",
    "license_manager": "healthy",
    "websocket_hub": "healthy"
  },
  "timestamp": "2026-01-16T10:30:00Z"
}
```

## License

Part of the AdinKhepra Protocol - See main repository for license details.
