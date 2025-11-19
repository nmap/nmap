# R-Map API Quick Start Guide

**Time to complete:** 10 minutes
**Prerequisites:** R-Map installed, basic API knowledge

## Table of Contents

- [Starting the API Server](#starting-the-api-server)
- [Authentication](#authentication)
- [Creating Your First Scan](#creating-your-first-scan)
- [Monitoring Scans](#monitoring-scans)
- [Code Examples](#code-examples)
- [Common Patterns](#common-patterns)

---

## Starting the API Server

### Option 1: Binary

```bash
# Start on default port (8080)
rmap-api

# Custom port
rmap-api --port 3000

# With environment variables
RUST_LOG=debug rmap-api --port 8080
```

### Option 2: Docker

```bash
docker run -d \
  --name rmap-api \
  -p 8080:8080 \
  -p 3001:3001 \
  ghcr.io/ununp3ntium115/r-map:latest \
  rmap-api
```

### Option 3: Kubernetes

```bash
helm install rmap rmap/rmap --namespace rmap --create-namespace
kubectl port-forward -n rmap svc/rmap-api 8080:8080
```

### Verify Server is Running

```bash
curl http://localhost:8080/api/v1/health
# Expected: {"status":"healthy","version":"1.0.0"}
```

---

## Authentication

### 1. Register a User

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secure_password_123"}'

# Response:
# {"message":"User registered successfully","user_id":"usr_1234567890"}
```

### 2. Login & Get Token

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secure_password_123"}' \
  | jq -r '.token')

echo "Token: $TOKEN"
```

### 3. Use Token in Requests

All subsequent requests need the Authorization header:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/scans
```

---

## Creating Your First Scan

### Basic Scan

```bash
SCAN_ID=$(curl -s -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["scanme.nmap.org"],
    "ports": "80,443",
    "scan_type": "connect"
  }' | jq -r '.scan_id')

echo "Scan created: $SCAN_ID"
```

### Scan with Service Detection

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["example.com"],
    "ports": "1-1000",
    "scan_type": "connect",
    "options": {
      "service_detection": true,
      "os_detection": false,
      "max_connections": 100,
      "timeout": 3
    },
    "output_format": "json"
  }'
```

### Network Scan

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.0/24"],
    "ports": "22,80,443,3306",
    "scan_type": "connect",
    "options": {
      "service_detection": true,
      "skip_ping": false,
      "max_connections": 200
    }
  }'
```

---

## Monitoring Scans

### Check Scan Status

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/scans/$SCAN_ID" | jq
```

**Response:**
```json
{
  "scan_id": "scan_123",
  "status": "running",
  "progress": {
    "total_targets": 1,
    "scanned_targets": 1,
    "percentage": 75.0,
    "total_ports": 1000,
    "scanned_ports": 750
  },
  "created_at": "2025-01-19T14:30:22Z",
  "started_at": "2025-01-19T14:30:25Z"
}
```

### Get Scan Results

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/scans/$SCAN_ID/results" | jq
```

### List All Scans

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/scans?status=completed&limit=10" | jq
```

### Cancel a Scan

```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/scans/$SCAN_ID"
```

---

## Code Examples

### Python

```python
import requests
import time

BASE_URL = "http://localhost:8080/api/v1"

# 1. Login
response = requests.post(
    f"{BASE_URL}/auth/login",
    json={"username": "admin", "password": "secure_password_123"}
)
token = response.json()["token"]

headers = {"Authorization": f"Bearer {token}"}

# 2. Create scan
response = requests.post(
    f"{BASE_URL}/scans",
    headers=headers,
    json={
        "targets": ["scanme.nmap.org"],
        "ports": "80,443",
        "scan_type": "connect",
        "options": {"service_detection": True}
    }
)
scan_id = response.json()["scan_id"]
print(f"Scan created: {scan_id}")

# 3. Wait for completion
while True:
    response = requests.get(f"{BASE_URL}/scans/{scan_id}", headers=headers)
    status = response.json()["status"]
    print(f"Status: {status}")

    if status == "completed":
        break
    elif status == "failed":
        print("Scan failed!")
        break

    time.sleep(5)

# 4. Get results
response = requests.get(f"{BASE_URL}/scans/{scan_id}/results", headers=headers)
results = response.json()
print(f"Found {results['scan_stats']['open_ports']} open ports")
```

### JavaScript (Node.js)

```javascript
const axios = require('axios');

const BASE_URL = 'http://localhost:8080/api/v1';

async function main() {
  // 1. Login
  const loginResp = await axios.post(`${BASE_URL}/auth/login`, {
    username: 'admin',
    password: 'secure_password_123'
  });
  const token = loginResp.data.token;

  const headers = { Authorization: `Bearer ${token}` };

  // 2. Create scan
  const scanResp = await axios.post(
    `${BASE_URL}/scans`,
    {
      targets: ['scanme.nmap.org'],
      ports: '80,443',
      scan_type: 'connect',
      options: { service_detection: true }
    },
    { headers }
  );
  const scanId = scanResp.data.scan_id;
  console.log(`Scan created: ${scanId}`);

  // 3. Wait for completion
  while (true) {
    const statusResp = await axios.get(
      `${BASE_URL}/scans/${scanId}`,
      { headers }
    );
    const status = statusResp.data.status;
    console.log(`Status: ${status}`);

    if (status === 'completed' || status === 'failed') break;

    await new Promise(resolve => setTimeout(resolve, 5000));
  }

  // 4. Get results
  const resultsResp = await axios.get(
    `${BASE_URL}/scans/${scanId}/results`,
    { headers }
  );
  console.log(`Found ${resultsResp.data.scan_stats.open_ports} open ports`);
}

main().catch(console.error);
```

### cURL Script

```bash
#!/bin/bash

# Configuration
BASE_URL="http://localhost:8080/api/v1"
USERNAME="admin"
PASSWORD="secure_password_123"

# Login
TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" \
  | jq -r '.token')

echo "Logged in, token: ${TOKEN:0:20}..."

# Create scan
SCAN_ID=$(curl -s -X POST "$BASE_URL/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["scanme.nmap.org"],
    "ports": "80,443",
    "scan_type": "connect",
    "options": {"service_detection": true}
  }' | jq -r '.scan_id')

echo "Scan created: $SCAN_ID"

# Poll for completion
while true; do
  STATUS=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "$BASE_URL/scans/$SCAN_ID" | jq -r '.status')

  echo "Status: $STATUS"

  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
    break
  fi

  sleep 5
done

# Get results
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/scans/$SCAN_ID/results" | jq > results.json

echo "Results saved to results.json"
```

---

## Common Patterns

### Parallel Scans

```python
import concurrent.futures

def run_scan(target):
    response = requests.post(
        f"{BASE_URL}/scans",
        headers=headers,
        json={"targets": [target], "ports": "80,443"}
    )
    return response.json()["scan_id"]

targets = ["example.com", "scanme.nmap.org", "google.com"]

with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
    scan_ids = list(executor.map(run_scan, targets))

print(f"Started {len(scan_ids)} scans")
```

### Scheduled Scans (with cron)

```bash
# /etc/cron.d/rmap-scan
0 2 * * * /usr/local/bin/run-nightly-scan.sh
```

**run-nightly-scan.sh:**
```bash
#!/bin/bash
TOKEN=$(/usr/local/bin/get-token.sh)
DATE=$(date +%Y%m%d)

curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.0/24"],
    "ports": "1-1000",
    "scan_type": "connect",
    "options": {"service_detection": true}
  }' > /var/log/rmap/scan-$DATE.json
```

### Webhook Integration

```python
# Wait for scan, then send webhook
response = requests.get(f"{BASE_URL}/scans/{scan_id}/results", headers=headers)
results = response.json()

# Send to webhook
webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
requests.post(webhook_url, json={
    "text": f"Scan completed: {results['scan_stats']['open_ports']} open ports found"
})
```

---

## WebSocket Real-time Updates

### JavaScript Example

```javascript
const WebSocket = require('ws');

const token = 'your-jwt-token-here';
const scanId = 'scan_123';
const ws = new WebSocket(
  `ws://localhost:8080/api/v1/scans/${scanId}/stream?token=${token}`
);

ws.on('message', (data) => {
  const event = JSON.parse(data);
  console.log(`Event: ${event.event}`);

  switch (event.event) {
    case 'scan_started':
      console.log(`Scan started: ${event.total_targets} targets`);
      break;
    case 'port_discovered':
      console.log(`Port found: ${event.host}:${event.port} (${event.state})`);
      break;
    case 'service_detected':
      console.log(`Service: ${event.service} ${event.version}`);
      break;
    case 'scan_completed':
      console.log(`Scan finished in ${event.duration_seconds}s`);
      ws.close();
      break;
  }
});
```

---

## Production Best Practices

### 1. Token Management

```python
# Store token securely
import os
from pathlib import Path

TOKEN_FILE = Path.home() / ".rmap" / "token"
TOKEN_FILE.parent.mkdir(exist_ok=True)

def save_token(token):
    TOKEN_FILE.write_text(token)
    TOKEN_FILE.chmod(0o600)  # Only owner can read

def load_token():
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text().strip()
    return None
```

### 2. Error Handling

```python
try:
    response = requests.post(url, headers=headers, json=data)
    response.raise_for_status()
except requests.exceptions.HTTPError as e:
    if e.response.status_code == 429:
        print("Rate limited, waiting 60s...")
        time.sleep(60)
        # Retry
    elif e.response.status_code == 401:
        print("Token expired, re-authenticating...")
        token = login()
    else:
        print(f"Error: {e.response.json()}")
```

### 3. Rate Limiting

```python
import time

class RateLimiter:
    def __init__(self, max_requests=10, window=60):
        self.max_requests = max_requests
        self.window = window
        self.requests = []

    def wait_if_needed(self):
        now = time.time()
        self.requests = [r for r in self.requests if r > now - self.window]

        if len(self.requests) >= self.max_requests:
            sleep_time = self.window - (now - self.requests[0])
            if sleep_time > 0:
                time.sleep(sleep_time)

        self.requests.append(time.time())

limiter = RateLimiter(max_requests=10, window=60)
limiter.wait_if_needed()  # Before each request
```

---

## Troubleshooting

### Connection Refused

```bash
# Check if server is running
curl http://localhost:8080/api/v1/health

# If not, start it
rmap-api --port 8080
```

### 401 Unauthorized

```bash
# Token expired (1 hour lifetime)
# Login again to get new token
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secure_password_123"}' \
  | jq -r '.token')
```

### 429 Too Many Requests

```bash
# Wait 60 seconds before retrying
# Reduce request rate
# Consider upgrading limits (if self-hosted)
```

---

## Next Steps

- **Full API Reference:** [/steering/API_REFERENCE.md](../steering/API_REFERENCE.md)
- **Deployment Guide:** [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
- **Performance Tuning:** [/steering/PERFORMANCE.md](../steering/PERFORMANCE.md)

---

**Happy scanning!** 🚀
