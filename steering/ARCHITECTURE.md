# R-Map Architecture: Node-RED & Svelte Integration

## Overview

R-Map is designed as a **modular network scanning backend** that integrates with:
- **Node-RED** for visual automation workflows
- **Svelte** for modern reactive UI components
- **RethinkDB/Redis** for real-time data persistence and streaming

This architecture enables R-Map to function as both a standalone CLI tool and a backend service for visual programming and web interfaces.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      FRONTEND LAYER                          │
├──────────────────────┬──────────────────────────────────────┤
│   Svelte Web UI      │        Node-RED Flows                │
│   - Dashboard        │        - Automation Nodes            │
│   - Real-time graphs │        - Scan Triggers               │
│   - Config panels    │        - Alert Handlers              │
└──────────────────────┴──────────────────────────────────────┘
           │                           │
           │ WebSocket/REST            │ MQTT/HTTP/WebSocket
           ▼                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      API LAYER                               │
├─────────────────────────────────────────────────────────────┤
│  REST API (Axum/Actix-Web)    WebSocket Server              │
│  - /api/scans                 - Real-time events             │
│  - /api/hosts                 - Progress updates            │
│  - /api/scripts               - Live results streaming      │
│  - /api/reports               - Bidirectional control       │
└─────────────────────────────────────────────────────────────┘
           │                           │
           │                           │
           ▼                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   CORE SCANNING ENGINE                       │
├─────────────────────────────────────────────────────────────┤
│  ScanEngine         ScriptEngine        ServiceDetection    │
│  - TCP Scanning     - Security Scripts  - Banner Grabbing   │
│  - UDP Scanning     - Vuln Checks       - Version Detection │
│  - OS Detection     - Custom Scripts    - Signature Match   │
└─────────────────────────────────────────────────────────────┘
           │                           │
           │                           │
           ▼                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   DATA PERSISTENCE LAYER                     │
├──────────────────────┬──────────────────────────────────────┤
│   RethinkDB          │           Redis                      │
│   - Scan results     │           - Real-time cache          │
│   - Host inventory   │           - Pub/Sub events           │
│   - Change feeds     │           - Session state            │
│   - Time-series data │           - Rate limiting            │
└──────────────────────┴──────────────────────────────────────┘
```

---

## Component Details

### 1. API Layer (NEW)

**Location:** `crates/rmap-api/`

**Purpose:** Expose R-Map functionality via REST and WebSocket APIs for external consumption.

#### REST Endpoints

```rust
// Scan Management
POST   /api/v1/scans              // Create new scan
GET    /api/v1/scans/:id          // Get scan status
GET    /api/v1/scans              // List all scans
DELETE /api/v1/scans/:id          // Cancel scan

// Results
GET    /api/v1/scans/:id/hosts    // Get discovered hosts
GET    /api/v1/scans/:id/ports    // Get open ports
GET    /api/v1/scans/:id/vulns    // Get vulnerabilities

// Scripts
GET    /api/v1/scripts            // List available scripts
POST   /api/v1/scripts/execute    // Run specific script

// Reports
GET    /api/v1/reports/:id/json   // JSON report
GET    /api/v1/reports/:id/pdf    // PDF report
GET    /api/v1/reports/:id/html   // HTML report
```

#### WebSocket Events

```rust
// Client → Server
{
  "type": "scan.start",
  "payload": {
    "targets": ["192.168.1.0/24"],
    "scan_type": "stealth",
    "ports": [1-65535]
  }
}

{
  "type": "scan.pause",
  "scan_id": "uuid"
}

// Server → Client
{
  "type": "scan.progress",
  "scan_id": "uuid",
  "progress": 45.2,
  "hosts_discovered": 12,
  "ports_scanned": 4500
}

{
  "type": "host.discovered",
  "scan_id": "uuid",
  "host": {
    "ip": "192.168.1.100",
    "hostname": "webserver.local",
    "os": "Linux 5.10",
    "ports": [...]
  }
}

{
  "type": "vulnerability.found",
  "scan_id": "uuid",
  "vulnerability": {
    "host": "192.168.1.100",
    "port": 443,
    "name": "SSL Heartbleed",
    "severity": "critical",
    "cve": "CVE-2014-0160"
  }
}
```

---

### 2. Database Integration (NEW)

**Location:** `crates/rmap-db/`

#### RethinkDB Schema

```javascript
// Scans Collection
{
  id: "uuid",
  created_at: timestamp,
  updated_at: timestamp,
  status: "pending|running|completed|failed",
  targets: ["192.168.1.0/24"],
  options: {
    scan_type: "stealth",
    ports: [1-65535],
    scripts: ["http-vuln-*"]
  },
  progress: 45.2,
  stats: {
    hosts_total: 256,
    hosts_up: 12,
    ports_scanned: 4500,
    vulnerabilities: 3
  }
}

// Hosts Collection
{
  id: "uuid",
  scan_id: "uuid",
  ip: "192.168.1.100",
  hostname: "webserver.local",
  mac: "00:11:22:33:44:55",
  os: {
    name: "Linux",
    version: "5.10",
    confidence: 95
  },
  ports: [
    {
      number: 80,
      state: "open",
      service: "http",
      version: "Apache 2.4.41"
    }
  ],
  vulnerabilities: [
    {
      name: "SSL Heartbleed",
      severity: "critical",
      cve: "CVE-2014-0160"
    }
  ],
  first_seen: timestamp,
  last_seen: timestamp
}

// Vulnerabilities Collection
{
  id: "uuid",
  scan_id: "uuid",
  host_id: "uuid",
  name: "SSL Heartbleed",
  description: "OpenSSL memory disclosure",
  severity: "critical",
  cvss: 7.5,
  cve: "CVE-2014-0160",
  port: 443,
  service: "https",
  evidence: "...",
  remediation: "Upgrade OpenSSL to 1.0.1g+",
  references: [...]
}
```

#### Redis Data Structures

```
// Active scan sessions (Hash)
scan:{scan_id} → {status, progress, start_time, pid}

// Real-time events (Pub/Sub)
events:scans → {type: "host.discovered", ...}
events:vulns → {type: "vulnerability.found", ...}

// Rate limiting (Sorted Set)
ratelimit:scans:{user_id} → {timestamp: scan_id}

// Temporary results cache (List)
cache:scan:{scan_id}:hosts → [host1, host2, ...]
```

---

### 3. Node-RED Custom Nodes (NEW)

**Location:** `node-red-contrib-rmap/`

#### Node Types

**3.1 Scanner Node**
```javascript
// node-red-contrib-rmap/nodes/scanner.js
{
  category: "network",
  color: "#4a90e2",
  defaults: {
    name: { value: "" },
    target: { value: "", required: true },
    scanType: { value: "stealth" },
    ports: { value: "1-1000" },
    scripts: { value: [] }
  },
  inputs: 1,  // Trigger input
  outputs: 2, // [0] Results, [1] Errors
  icon: "network.png",
  label: function() {
    return this.name || "R-Map Scanner";
  }
}
```

**3.2 Script Runner Node**
```javascript
// node-red-contrib-rmap/nodes/script-runner.js
{
  category: "security",
  defaults: {
    scriptName: { value: "http-vuln-*" },
    target: { value: "", required: true },
    timeout: { value: 300 }
  },
  inputs: 1,
  outputs: 1
}
```

**3.3 Results Filter Node**
```javascript
// node-red-contrib-rmap/nodes/filter.js
{
  category: "network",
  defaults: {
    filterType: { value: "severity" },
    minSeverity: { value: "medium" },
    portRange: { value: "" },
    serviceType: { value: "" }
  },
  inputs: 1,
  outputs: 1
}
```

#### Node-RED Flow Example

```json
[
  {
    "id": "scanner1",
    "type": "rmap-scanner",
    "name": "Scan Internal Network",
    "target": "192.168.1.0/24",
    "scanType": "stealth",
    "wires": [["filter1"], ["error-handler"]]
  },
  {
    "id": "filter1",
    "type": "rmap-filter",
    "filterType": "severity",
    "minSeverity": "high",
    "wires": [["alert1", "db-save"]]
  },
  {
    "id": "alert1",
    "type": "email",
    "to": "security@company.com",
    "subject": "Critical Vulnerabilities Found"
  },
  {
    "id": "db-save",
    "type": "rethinkdb-insert",
    "database": "security",
    "table": "scan_results"
  }
]
```

---

### 4. Svelte Component Data Contracts (NEW)

**Location:** `svelte-frontend/src/lib/types/`

#### TypeScript Interfaces

```typescript
// types/scan.ts
export interface Scan {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  targets: string[];
  created_at: Date;
  updated_at: Date;
  progress: number;
  stats: ScanStats;
  options: ScanOptions;
}

export interface ScanStats {
  hosts_total: number;
  hosts_up: number;
  hosts_down: number;
  ports_scanned: number;
  ports_open: number;
  vulnerabilities: number;
  duration: number; // seconds
}

export interface ScanOptions {
  scan_type: 'stealth' | 'connect' | 'udp' | 'comprehensive';
  ports: string; // "1-65535" or "80,443,8080"
  timing: 0 | 1 | 2 | 3 | 4 | 5; // T0-T5
  scripts: string[];
  service_detection: boolean;
  os_detection: boolean;
}

// types/host.ts
export interface Host {
  id: string;
  scan_id: string;
  ip: string;
  hostname?: string;
  mac?: string;
  os?: OSInfo;
  ports: Port[];
  vulnerabilities: Vulnerability[];
  first_seen: Date;
  last_seen: Date;
}

export interface Port {
  number: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered' | 'open|filtered';
  service?: string;
  version?: string;
  banner?: string;
}

export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss: number;
  cve?: string;
  port: number;
  service: string;
  evidence: string;
  remediation: string;
  references: string[];
}

export interface OSInfo {
  name: string;
  version: string;
  confidence: number; // 0-100
  cpe?: string;
}

// types/events.ts
export type ScanEvent =
  | { type: 'scan.started'; scan_id: string }
  | { type: 'scan.progress'; scan_id: string; progress: number; stats: ScanStats }
  | { type: 'host.discovered'; scan_id: string; host: Host }
  | { type: 'port.open'; scan_id: string; host: string; port: Port }
  | { type: 'vulnerability.found'; scan_id: string; vulnerability: Vulnerability }
  | { type: 'scan.completed'; scan_id: string; stats: ScanStats }
  | { type: 'scan.error'; scan_id: string; error: string };
```

#### Svelte Store Integration

```typescript
// stores/scans.ts
import { writable, derived } from 'svelte/store';
import type { Scan, ScanEvent } from '$lib/types';

export const scans = writable<Map<string, Scan>>(new Map());
export const activeScans = derived(scans, $scans =>
  Array.from($scans.values()).filter(s => s.status === 'running')
);

// WebSocket connection
export function connectToScanner() {
  const ws = new WebSocket('ws://localhost:8080/ws');

  ws.onmessage = (event) => {
    const scanEvent: ScanEvent = JSON.parse(event.data);

    switch (scanEvent.type) {
      case 'scan.progress':
        scans.update(map => {
          const scan = map.get(scanEvent.scan_id);
          if (scan) {
            scan.progress = scanEvent.progress;
            scan.stats = scanEvent.stats;
          }
          return map;
        });
        break;

      case 'host.discovered':
        // Update scan with new host
        break;

      case 'vulnerability.found':
        // Add vulnerability to scan
        break;
    }
  };

  return ws;
}
```

---

### 5. API Server Implementation Plan

**Crate:** `crates/rmap-api/`

**Dependencies:**
```toml
[dependencies]
axum = "0.7"           # Web framework
tokio = { version = "1", features = ["full"] }
tower = "0.4"          # Middleware
tower-http = { version = "0.5", features = ["cors", "trace"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
uuid = { version = "1.0", features = ["v4", "serde"] }
tracing = "0.1"
tracing-subscriber = "0.3"

# WebSocket
axum-extra = { version = "0.9", features = ["typed-header"] }
tokio-tungstenite = "0.21"

# Database
rethinkdb = "0.9"      # RethinkDB client
redis = { version = "0.24", features = ["tokio-comp", "connection-manager"] }

# R-Map core
nmap-core = { path = "../nmap-core" }
nmap-engine = { path = "../nmap-engine" }
```

**Structure:**
```
crates/rmap-api/
├── src/
│   ├── main.rs              # API server entry point
│   ├── routes/
│   │   ├── mod.rs
│   │   ├── scans.rs         # Scan management endpoints
│   │   ├── hosts.rs         # Host data endpoints
│   │   ├── scripts.rs       # Script execution endpoints
│   │   └── reports.rs       # Report generation endpoints
│   ├── websocket/
│   │   ├── mod.rs
│   │   ├── handler.rs       # WebSocket connection handler
│   │   └── events.rs        # Event serialization
│   ├── db/
│   │   ├── mod.rs
│   │   ├── rethinkdb.rs     # RethinkDB operations
│   │   └── redis.rs         # Redis operations
│   ├── models/
│   │   ├── mod.rs
│   │   ├── scan.rs          # Scan data models
│   │   ├── host.rs          # Host data models
│   │   └── vulnerability.rs # Vulnerability models
│   └── services/
│       ├── mod.rs
│       ├── scan_service.rs  # Scan orchestration
│       └── event_bus.rs     # Event distribution
└── Cargo.toml
```

---

### 6. Node-RED Integration Package

**Structure:**
```
node-red-contrib-rmap/
├── package.json
├── nodes/
│   ├── scanner.js           # Scanner node implementation
│   ├── scanner.html         # Scanner node UI
│   ├── script-runner.js     # Script execution node
│   ├── script-runner.html   # Script execution UI
│   ├── filter.js            # Results filter node
│   └── filter.html          # Filter UI
├── lib/
│   └── rmap-client.js       # R-Map API client library
└── examples/
    └── flows.json           # Example flows
```

**package.json:**
```json
{
  "name": "node-red-contrib-rmap",
  "version": "1.0.0",
  "description": "R-Map network scanner nodes for Node-RED",
  "node-red": {
    "nodes": {
      "scanner": "nodes/scanner.js",
      "script-runner": "nodes/script-runner.js",
      "filter": "nodes/filter.js"
    }
  },
  "dependencies": {
    "axios": "^1.6.0",
    "ws": "^8.14.0"
  },
  "keywords": [
    "node-red",
    "network",
    "scanner",
    "security",
    "rmap",
    "nmap"
  ]
}
```

---

### 7. Svelte Frontend Structure

**Location:** `svelte-frontend/`

```
svelte-frontend/
├── src/
│   ├── routes/
│   │   ├── +page.svelte           # Dashboard
│   │   ├── scans/
│   │   │   ├── +page.svelte       # Scan list
│   │   │   └── [id]/+page.svelte  # Scan details
│   │   ├── hosts/
│   │   │   └── +page.svelte       # Host inventory
│   │   └── reports/
│   │       └── +page.svelte       # Report viewer
│   ├── lib/
│   │   ├── components/
│   │   │   ├── ScanForm.svelte    # New scan configuration
│   │   │   ├── HostCard.svelte    # Host details card
│   │   │   ├── PortTable.svelte   # Port list table
│   │   │   ├── VulnAlert.svelte   # Vulnerability alert
│   │   │   └── ScanProgress.svelte # Real-time progress
│   │   ├── stores/
│   │   │   ├── scans.ts           # Scan state management
│   │   │   ├── websocket.ts       # WebSocket connection
│   │   │   └── settings.ts        # User settings
│   │   ├── types/
│   │   │   ├── scan.ts            # Scan types
│   │   │   ├── host.ts            # Host types
│   │   │   └── events.ts          # Event types
│   │   └── api/
│   │       └── client.ts          # API client
│   └── app.html
├── static/
└── svelte.config.js
```

---

## Implementation Priority

### Phase 1: Core API Infrastructure (Week 1-2)
- [ ] Create `rmap-api` crate with Axum
- [ ] Implement REST endpoints for scan management
- [ ] Add WebSocket server for real-time events
- [ ] Database integration (RethinkDB + Redis)
- [ ] Basic authentication & rate limiting

### Phase 2: Node-RED Integration (Week 3)
- [ ] Create `node-red-contrib-rmap` package
- [ ] Implement scanner node
- [ ] Implement script runner node
- [ ] Implement filter node
- [ ] Publish to npm registry

### Phase 3: Svelte Frontend (Week 4-5)
- [ ] Initialize SvelteKit project
- [ ] Create dashboard with real-time updates
- [ ] Implement scan configuration UI
- [ ] Build host inventory viewer
- [ ] Add vulnerability reporting

### Phase 4: Advanced Features (Week 6-8)
- [ ] Advanced TCP scans (ACK, FIN, NULL, Xmas)
- [ ] Security scripts framework (20+ scripts)
- [ ] Service signature expansion (100+ services)
- [ ] Enhanced reporting (PDF, HTML)
- [ ] Multi-user support & RBAC

---

## Communication Protocols

### REST API Request/Response

**Create Scan:**
```bash
POST /api/v1/scans
Content-Type: application/json

{
  "targets": ["192.168.1.0/24"],
  "scan_type": "stealth",
  "ports": "1-1000",
  "scripts": ["http-vuln-*"],
  "options": {
    "timing": 3,
    "service_detection": true,
    "os_detection": false
  }
}

Response: 201 Created
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "created_at": "2025-11-17T10:30:00Z"
}
```

**Get Scan Status:**
```bash
GET /api/v1/scans/550e8400-e29b-41d4-a716-446655440000

Response: 200 OK
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "progress": 45.2,
  "stats": {
    "hosts_up": 12,
    "ports_scanned": 4500,
    "vulnerabilities": 3
  },
  "started_at": "2025-11-17T10:30:05Z",
  "estimated_completion": "2025-11-17T10:45:00Z"
}
```

### WebSocket Protocol

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

// Subscribe to scan events
ws.send(JSON.stringify({
  type: 'subscribe',
  scan_id: '550e8400-e29b-41d4-a716-446655440000'
}));

// Receive events
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // Handle different event types
};
```

---

## Security Considerations

1. **Authentication:** JWT tokens for API access
2. **Authorization:** Role-based access control (Admin, User, Viewer)
3. **Rate Limiting:** Per-user scan limits in Redis
4. **Input Validation:** Strict target validation (no SSRF)
5. **Network Isolation:** Scan targets must be in allowed ranges
6. **Audit Logging:** All scans logged to database
7. **Encryption:** TLS for API, WSS for WebSocket

---

## Deployment Architecture

```
┌─────────────────────────────────────────────────┐
│              Load Balancer (Nginx)              │
└─────────────────┬───────────────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
┌───────▼────────┐  ┌──────▼────────┐
│  Svelte SPA    │  │  API Server   │
│  (Static CDN)  │  │  (Rust/Axum)  │
└────────────────┘  └───────┬───────┘
                            │
                  ┌─────────┴─────────┐
                  │                   │
        ┌─────────▼────────┐ ┌───────▼────────┐
        │   RethinkDB      │ │     Redis      │
        │  (Persistent)    │ │    (Cache)     │
        └──────────────────┘ └────────────────┘
```

---

## Next Steps

1. **Immediate:** Create `rmap-api` crate with basic REST server
2. **Short-term:** Implement WebSocket events for real-time updates
3. **Medium-term:** Build Node-RED nodes package
4. **Long-term:** Complete Svelte frontend with all features

This architecture transforms R-Map from a CLI tool into a comprehensive network scanning platform with visual automation and modern web UI.
