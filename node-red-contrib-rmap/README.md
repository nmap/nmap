# node-red-contrib-rmap

R-Map network scanner nodes for Node-RED, enabling visual automation of security scanning and network discovery workflows.

## Features

- **Scanner Node**: Execute network scans with configurable options
- **Script Runner**: Run security scripts on discovered hosts
- **Filter Node**: Filter scan results by severity, port, service
- **Webhook Node**: Receive real-time scan events via WebSocket

## Installation

```bash
npm install node-red-contrib-rmap
```

Or install directly from Node-RED's palette manager.

## Prerequisites

- R-Map API server running (default: `http://localhost:8080`)
- Node-RED v3.0.0 or higher
- Node.js v18.0.0 or higher

## Nodes

### Scanner Node

Executes network scans on specified targets.

**Inputs:**
- `msg.payload`: Target specification (IP, CIDR, hostname)
- `msg.scanType`: Type of scan (`stealth`, `connect`, `udp`, `comprehensive`)
- `msg.ports`: Port specification (`1-1000`, `80,443`, etc.)

**Outputs:**
1. Scan results (hosts, ports, services)
2. Errors

**Configuration:**
- Target: IP address, CIDR range, or hostname
- Scan Type: Stealth (SYN), Connect, UDP, Comprehensive
- Ports: Port range or specific ports
- Scripts: Security scripts to run
- Timing: T0-T5 timing template
- Options: Service detection, OS detection, skip ping

**Example Flow:**
```javascript
[
    {
        "id": "scanner1",
        "type": "rmap-scanner",
        "name": "Scan Network",
        "target": "192.168.1.0/24",
        "scanType": "stealth",
        "ports": "1-1000",
        "timing": 3,
        "serviceDetection": true,
        "osDetection": false,
        "wires": [["results"], ["errors"]]
    }
]
```

### Script Runner Node

Executes security scripts on targets.

**Inputs:**
- `msg.payload`: Target host
- `msg.scripts`: Array of script names to run

**Outputs:**
- Script results with vulnerabilities found

**Configuration:**
- Script Names: Wildcard patterns (`http-vuln-*`)
- Timeout: Script execution timeout

**Example:**
```javascript
{
    "id": "script1",
    "type": "rmap-script-runner",
    "scriptName": "http-vuln-*",
    "timeout": 300,
    "wires": [["vulns"]]
}
```

### Filter Node

Filters scan results based on criteria.

**Inputs:**
- `msg.payload`: Scan results or vulnerability list

**Outputs:**
- Filtered results matching criteria

**Configuration:**
- Filter Type: Severity, Port, Service
- Min Severity: Critical, High, Medium, Low
- Port Range: Filter by port numbers
- Service Type: Filter by service name

**Example:**
```javascript
{
    "id": "filter1",
    "type": "rmap-filter",
    "filterType": "severity",
    "minSeverity": "high",
    "wires": [["critical-vulns"]]
}
```

### Webhook Node

Receives real-time scan events via WebSocket.

**Outputs:**
- Real-time scan events (progress, hosts discovered, vulnerabilities found)

**Configuration:**
- WebSocket URL: R-Map API WebSocket endpoint
- Subscribe To: All scans or specific scan ID

**Events:**
- `scan.started`
- `scan.progress`
- `host.discovered`
- `port.open`
- `vulnerability.found`
- `scan.completed`

## Example Workflows

### Automated Security Scanning

```
[Inject] → [Scanner] → [Filter (High+)] → [Email Alert]
                     ↓
                  [RethinkDB Insert]
```

### Continuous Network Monitoring

```
[Scheduler] → [Scanner] → [Webhook] → [Dashboard]
                                    ↓
                                 [Alert on Critical]
```

### Vulnerability Assessment Pipeline

```
[Asset List] → [Scanner] → [Script Runner] → [Filter] → [Report Generator]
                                                       ↓
                                                   [Ticketing System]
```

## API Server Configuration

The nodes connect to the R-Map API server. Configure the server URL in settings:

```javascript
// settings.js
module.exports = {
    rmapApiUrl: process.env.RMAP_API_URL || 'http://localhost:8080'
}
```

## Development

```bash
# Clone repository
git clone https://github.com/Ununp3ntium115/R-map.git
cd R-map/node-red-contrib-rmap

# Install dependencies
npm install

# Link to Node-RED
npm link
cd ~/.node-red
npm link node-red-contrib-rmap

# Restart Node-RED
node-red
```

## Testing

```bash
npm test
```

## License

MIT

## Links

- [R-Map GitHub Repository](https://github.com/Ununp3ntium115/R-map)
- [Node-RED](https://nodered.org/)
- [Documentation](https://github.com/Ununp3ntium115/R-map/tree/main/steering)
