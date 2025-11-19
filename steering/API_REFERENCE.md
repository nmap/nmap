# R-Map REST API Reference

**Version:** 1.0.0
**Base URL:** `http://localhost:8080/api/v1`
**Authentication:** JWT Bearer Token
**Content-Type:** `application/json`

## Table of Contents

- [Authentication](#authentication)
- [Core Endpoints](#core-endpoints)
- [Scan Management](#scan-management)
- [WebSocket API](#websocket-api)
- [Rate Limiting](#rate-limiting)
- [Error Handling](#error-handling)
- [Code Examples](#code-examples)

---

## Authentication

### Register a New User

**Endpoint:** `POST /api/v1/auth/register`

**Request Body:**
```json
{
  "username": "admin",
  "password": "secure_password_123"
}
```

**Response (201 Created):**
```json
{
  "message": "User registered successfully",
  "user_id": "usr_1234567890"
}
```

**Error (400 Bad Request):**
```json
{
  "error": "Username already exists"
}
```

### Login

**Endpoint:** `POST /api/v1/auth/login`

**Request Body:**
```json
{
  "username": "admin",
  "password": "secure_password_123"
}
```

**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

**Error (401 Unauthorized):**
```json
{
  "error": "Invalid credentials"
}
```

### Using the Token

All authenticated requests must include the JWT token in the Authorization header:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Token Expiration:** 1 hour (3600 seconds)

---

## Core Endpoints

### Health Check

**Endpoint:** `GET /api/v1/health`

**Authentication:** Not required

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 86400
}
```

### System Information

**Endpoint:** `GET /api/v1/info`

**Authentication:** Required

**Response (200 OK):**
```json
{
  "version": "1.0.0",
  "build_date": "2025-01-19",
  "rust_version": "1.75.0",
  "features": {
    "tcp_scan": true,
    "udp_scan": true,
    "service_detection": true,
    "os_detection": true,
    "security_scripts": true,
    "output_formats": ["json", "xml", "html", "pdf", "grepable", "markdown", "csv", "sqlite"]
  },
  "limits": {
    "max_concurrent_scans": 10,
    "max_targets_per_scan": 1024,
    "max_ports_per_scan": 65535
  }
}
```

---

## Scan Management

### Create a New Scan

**Endpoint:** `POST /api/v1/scans`

**Authentication:** Required

**Request Body:**
```json
{
  "targets": ["example.com", "192.168.1.1", "10.0.0.0/24"],
  "ports": "1-1000,3306,5432,8080",
  "scan_type": "syn",
  "options": {
    "service_detection": true,
    "os_detection": true,
    "skip_ping": false,
    "max_connections": 100,
    "timeout": 3,
    "scripts": ["http-vuln", "ssh-auth"]
  },
  "output_format": "json"
}
```

**Field Descriptions:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `targets` | array[string] | Yes | - | List of targets (IPs, hostnames, CIDR) |
| `ports` | string | No | "1-1000" | Port specification |
| `scan_type` | string | No | "connect" | Scan type: `connect`, `syn`, `ack`, `fin`, `null`, `xmas`, `udp` |
| `options.service_detection` | boolean | No | false | Enable service/version detection |
| `options.os_detection` | boolean | No | false | Enable OS fingerprinting |
| `options.skip_ping` | boolean | No | false | Skip host discovery |
| `options.max_connections` | integer | No | 100 | Max concurrent connections (1-1000) |
| `options.timeout` | integer | No | 3 | Connection timeout in seconds (1-30) |
| `options.scripts` | array[string] | No | [] | Security scripts to run |
| `output_format` | string | No | "json" | Output format |

**Response (202 Accepted):**
```json
{
  "scan_id": "scan_20250119_143022_a1b2c3",
  "status": "queued",
  "created_at": "2025-01-19T14:30:22Z",
  "websocket_url": "ws://localhost:8080/api/v1/scans/scan_20250119_143022_a1b2c3/stream"
}
```

**Error (429 Too Many Requests):**
```json
{
  "error": "Rate limit exceeded",
  "retry_after": 60
}
```

### Get Scan Status

**Endpoint:** `GET /api/v1/scans/{scan_id}`

**Authentication:** Required

**Response (200 OK):**
```json
{
  "scan_id": "scan_20250119_143022_a1b2c3",
  "status": "running",
  "progress": {
    "total_targets": 256,
    "scanned_targets": 128,
    "percentage": 50.0,
    "total_ports": 256000,
    "scanned_ports": 128000
  },
  "created_at": "2025-01-19T14:30:22Z",
  "started_at": "2025-01-19T14:30:25Z",
  "estimated_completion": "2025-01-19T14:35:25Z"
}
```

**Status Values:**
- `queued` - Scan is queued, waiting to start
- `running` - Scan is actively running
- `completed` - Scan finished successfully
- `failed` - Scan failed with errors
- `cancelled` - Scan was cancelled by user

### Get Scan Results

**Endpoint:** `GET /api/v1/scans/{scan_id}/results`

**Authentication:** Required

**Query Parameters:**
- `format` (optional): Output format (json, xml, html, etc.)

**Response (200 OK):**
```json
{
  "scan_id": "scan_20250119_143022_a1b2c3",
  "status": "completed",
  "start_time": "2025-01-19T14:30:25Z",
  "end_time": "2025-01-19T14:35:48Z",
  "duration_seconds": 323,
  "targets": ["example.com"],
  "scan_type": "syn",
  "results": [
    {
      "host": "93.184.216.34",
      "hostname": "example.com",
      "status": "up",
      "latency_ms": 12.5,
      "ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "http",
          "version": "Apache/2.4.52 (Ubuntu)",
          "banner": "Apache/2.4.52 (Ubuntu)"
        },
        {
          "port": 443,
          "protocol": "tcp",
          "state": "open",
          "service": "https",
          "version": "Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2"
        }
      ],
      "os": {
        "name": "Linux 5.15",
        "family": "Linux",
        "vendor": "Linux",
        "accuracy": 95,
        "cpe": "cpe:/o:linux:linux_kernel:5.15",
        "detection_methods": ["active_fingerprint", "passive_ttl", "http_headers"]
      },
      "vulnerabilities": [
        {
          "script": "http-vuln-cve2021-41773",
          "severity": "high",
          "description": "Apache HTTP Server 2.4.49-2.4.50 Path Traversal",
          "references": ["CVE-2021-41773"]
        }
      ]
    }
  ],
  "scan_stats": {
    "total_hosts": 1,
    "hosts_up": 1,
    "hosts_down": 0,
    "total_ports_scanned": 1000,
    "open_ports": 2,
    "closed_ports": 998,
    "filtered_ports": 0
  }
}
```

### List All Scans

**Endpoint:** `GET /api/v1/scans`

**Authentication:** Required

**Query Parameters:**
- `status` (optional): Filter by status (queued, running, completed, failed)
- `limit` (optional): Number of results (default: 50, max: 100)
- `offset` (optional): Pagination offset (default: 0)

**Response (200 OK):**
```json
{
  "scans": [
    {
      "scan_id": "scan_20250119_143022_a1b2c3",
      "status": "completed",
      "targets_count": 1,
      "created_at": "2025-01-19T14:30:22Z",
      "duration_seconds": 323
    },
    {
      "scan_id": "scan_20250119_120015_d4e5f6",
      "status": "running",
      "targets_count": 256,
      "created_at": "2025-01-19T12:00:15Z",
      "progress": 45.2
    }
  ],
  "total_count": 127,
  "limit": 50,
  "offset": 0
}
```

### Cancel a Scan

**Endpoint:** `DELETE /api/v1/scans/{scan_id}`

**Authentication:** Required

**Response (200 OK):**
```json
{
  "scan_id": "scan_20250119_143022_a1b2c3",
  "status": "cancelled",
  "message": "Scan cancelled successfully"
}
```

### Export Scan Results

**Endpoint:** `GET /api/v1/scans/{scan_id}/export`

**Authentication:** Required

**Query Parameters:**
- `format` (required): Export format (json, xml, html, pdf, grepable, markdown, csv, sqlite)

**Response:** Binary file download with appropriate Content-Type

**Example:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/scans/scan_123/export?format=pdf" \
  -o scan-report.pdf
```

---

## WebSocket API

### Real-time Scan Progress

**Endpoint:** `ws://localhost:8080/api/v1/scans/{scan_id}/stream`

**Authentication:** Token in query parameter: `?token=eyJhbGc...`

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:8080/api/v1/scans/scan_123/stream?token=' + token);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Event:', data);
};
```

**Event Types:**

#### 1. Scan Started
```json
{
  "event": "scan_started",
  "timestamp": "2025-01-19T14:30:25Z",
  "scan_id": "scan_123",
  "total_targets": 256
}
```

#### 2. Host Discovery
```json
{
  "event": "host_discovered",
  "timestamp": "2025-01-19T14:30:27Z",
  "host": "192.168.1.1",
  "hostname": "router.local",
  "latency_ms": 2.5
}
```

#### 3. Port Scan Progress
```json
{
  "event": "port_scan_progress",
  "timestamp": "2025-01-19T14:30:30Z",
  "host": "192.168.1.1",
  "ports_scanned": 500,
  "total_ports": 1000,
  "percentage": 50.0
}
```

#### 4. Port Discovered
```json
{
  "event": "port_discovered",
  "timestamp": "2025-01-19T14:30:32Z",
  "host": "192.168.1.1",
  "port": 80,
  "protocol": "tcp",
  "state": "open"
}
```

#### 5. Service Detected
```json
{
  "event": "service_detected",
  "timestamp": "2025-01-19T14:30:35Z",
  "host": "192.168.1.1",
  "port": 80,
  "service": "http",
  "version": "nginx/1.18.0"
}
```

#### 6. OS Detected
```json
{
  "event": "os_detected",
  "timestamp": "2025-01-19T14:30:40Z",
  "host": "192.168.1.1",
  "os": "Linux 5.4",
  "accuracy": 95
}
```

#### 7. Vulnerability Found
```json
{
  "event": "vulnerability_found",
  "timestamp": "2025-01-19T14:30:45Z",
  "host": "192.168.1.1",
  "port": 80,
  "vulnerability": "CVE-2021-41773",
  "severity": "high"
}
```

#### 8. Scan Completed
```json
{
  "event": "scan_completed",
  "timestamp": "2025-01-19T14:35:48Z",
  "scan_id": "scan_123",
  "duration_seconds": 323,
  "hosts_up": 12,
  "open_ports": 48
}
```

#### 9. Error
```json
{
  "event": "error",
  "timestamp": "2025-01-19T14:30:50Z",
  "error": "Connection timeout for host 192.168.1.100",
  "severity": "warning"
}
```

---

## Rate Limiting

R-Map API implements rate limiting to prevent abuse:

### Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/api/v1/auth/*` | 5 requests | 1 minute |
| `/api/v1/scans` (POST) | 2 scans | 1 minute |
| `/api/v1/scans` (GET) | 60 requests | 1 minute |
| `/api/v1/scans/{id}` | 60 requests | 1 minute |
| General API | 100 requests | 1 minute |

### Rate Limit Headers

Every API response includes rate limit headers:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1705675890
```

### Rate Limit Exceeded Response

**Status:** 429 Too Many Requests

```json
{
  "error": "Rate limit exceeded",
  "retry_after": 30,
  "limit": 60,
  "window_seconds": 60
}
```

---

## Error Handling

### Standard Error Response Format

```json
{
  "error": "Error message",
  "details": "Additional context about the error",
  "request_id": "req_1234567890",
  "timestamp": "2025-01-19T14:30:22Z"
}
```

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request succeeded |
| 201 | Created | Resource created successfully |
| 202 | Accepted | Request accepted for processing |
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Authentication required or failed |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error occurred |
| 503 | Service Unavailable | Service temporarily unavailable |

### Common Error Scenarios

#### Invalid Target
```json
{
  "error": "Invalid target specification",
  "details": "Target '999.999.999.999' is not a valid IP address",
  "field": "targets[0]"
}
```

#### SSRF Protection
```json
{
  "error": "Target blocked by SSRF protection",
  "details": "Target '169.254.169.254' is a cloud metadata endpoint",
  "blocked_reason": "cloud_metadata"
}
```

#### Scan Not Found
```json
{
  "error": "Scan not found",
  "details": "Scan ID 'scan_invalid' does not exist",
  "scan_id": "scan_invalid"
}
```

---

## Code Examples

### Python (requests + websockets)

```python
import requests
import websockets
import asyncio
import json

BASE_URL = "http://localhost:8080/api/v1"

# 1. Register and login
def login(username, password):
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": username, "password": password}
    )
    return response.json()["token"]

# 2. Create a scan
def create_scan(token, targets, ports="1-1000"):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(
        f"{BASE_URL}/scans",
        headers=headers,
        json={
            "targets": targets,
            "ports": ports,
            "scan_type": "connect",
            "options": {
                "service_detection": True,
                "os_detection": True
            }
        }
    )
    return response.json()["scan_id"]

# 3. Monitor scan progress via WebSocket
async def monitor_scan(token, scan_id):
    uri = f"ws://localhost:8080/api/v1/scans/{scan_id}/stream?token={token}"
    async with websockets.connect(uri) as websocket:
        while True:
            message = await websocket.recv()
            event = json.loads(message)
            print(f"Event: {event['event']}")

            if event['event'] == 'scan_completed':
                break

# 4. Get results
def get_results(token, scan_id):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(
        f"{BASE_URL}/scans/{scan_id}/results",
        headers=headers
    )
    return response.json()

# Main workflow
token = login("admin", "password")
scan_id = create_scan(token, ["scanme.nmap.org"], "80,443")
print(f"Scan started: {scan_id}")

# Monitor progress
asyncio.run(monitor_scan(token, scan_id))

# Get final results
results = get_results(token, scan_id)
print(json.dumps(results, indent=2))
```

### JavaScript (Node.js)

```javascript
const axios = require('axios');
const WebSocket = require('ws');

const BASE_URL = 'http://localhost:8080/api/v1';

// 1. Login
async function login(username, password) {
  const response = await axios.post(`${BASE_URL}/auth/login`, {
    username,
    password
  });
  return response.data.token;
}

// 2. Create scan
async function createScan(token, targets, ports = '1-1000') {
  const response = await axios.post(
    `${BASE_URL}/scans`,
    {
      targets,
      ports,
      scan_type: 'connect',
      options: {
        service_detection: true,
        os_detection: true
      }
    },
    {
      headers: { Authorization: `Bearer ${token}` }
    }
  );
  return response.data.scan_id;
}

// 3. Monitor via WebSocket
function monitorScan(token, scanId) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(
      `ws://localhost:8080/api/v1/scans/${scanId}/stream?token=${token}`
    );

    ws.on('message', (data) => {
      const event = JSON.parse(data);
      console.log('Event:', event.event);

      if (event.event === 'scan_completed') {
        ws.close();
        resolve();
      }
    });

    ws.on('error', reject);
  });
}

// 4. Get results
async function getResults(token, scanId) {
  const response = await axios.get(
    `${BASE_URL}/scans/${scanId}/results`,
    {
      headers: { Authorization: `Bearer ${token}` }
    }
  );
  return response.data;
}

// Main workflow
(async () => {
  const token = await login('admin', 'password');
  const scanId = await createScan(token, ['scanme.nmap.org'], '80,443');
  console.log('Scan started:', scanId);

  await monitorScan(token, scanId);

  const results = await getResults(token, scanId);
  console.log(JSON.stringify(results, null, 2));
})();
```

### cURL Examples

```bash
# Login
TOKEN=$(curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  | jq -r '.token')

# Create scan
SCAN_ID=$(curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["scanme.nmap.org"],
    "ports": "80,443",
    "options": {
      "service_detection": true
    }
  }' | jq -r '.scan_id')

echo "Scan ID: $SCAN_ID"

# Check status
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/scans/$SCAN_ID" | jq

# Get results
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/scans/$SCAN_ID/results" | jq

# Export as PDF
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/scans/$SCAN_ID/export?format=pdf" \
  -o scan-report.pdf
```

---

## Best Practices

### 1. Token Management
- Store tokens securely (environment variables, key vault)
- Refresh tokens before expiration
- Use HTTPS in production

### 2. Rate Limiting
- Implement exponential backoff on 429 errors
- Batch scan requests when possible
- Use WebSocket for real-time updates instead of polling

### 3. Error Handling
- Check HTTP status codes
- Parse error responses for details
- Log request_id for debugging

### 4. Performance
- Use appropriate scan types (connect vs SYN)
- Limit concurrent scans
- Specify port ranges carefully

### 5. Security
- Never expose JWT tokens in logs
- Validate all user inputs
- Use SSRF protection (enabled by default)

---

**Document Version:** 1.0
**Last Updated:** 2025-01-19
**Support:** https://github.com/Ununp3ntium115/R-map/issues
