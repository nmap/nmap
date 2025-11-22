# PYRO + Claude Integration: Deployment Modes

The `pyro-mcp-server` can run in **two modes**:

1. **MCP Integration Mode** (recommended) - Integrated with Claude Desktop/Code
2. **Standalone HTTP API Mode** - Runs as independent web server

---

## Mode 1: MCP Integration (Recommended)

**Best for:** Claude Desktop, Claude Code, AI-driven workflows

### How It Works

The server communicates via **JSON-RPC 2.0 over stdin/stdout** following the Model Context Protocol.

### Setup

1. **Build the MCP server:**
   ```bash
   cargo build --release --bin pyro-mcp-server
   ```

2. **Configure MCP:**

   **Linux/macOS:** `~/.config/claude/claude_desktop_config.json`
   ```json
   {
     "mcpServers": {
       "pyro-claude-integration": {
         "command": "/home/user/R-map/target/release/pyro-mcp-server",
         "args": [],
         "env": {
           "PYRO_DB_PATH": "/var/lib/pyro/integration.db",
           "RUST_LOG": "info"
         }
       }
     }
   }
   ```

   **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
   ```json
   {
     "mcpServers": {
       "pyro-claude-integration": {
         "command": "C:\\path\\to\\R-map\\target\\release\\pyro-mcp-server.exe",
         "args": [],
         "env": {
           "PYRO_DB_PATH": "C:\\pyro\\integration.db",
           "RUST_LOG": "info"
         }
       }
     }
   }
   ```

3. **Restart Claude Desktop/Code**

4. **Test:**
   Ask Claude: "List all available PYRO and R-Map MCP tools"

### Available Tools (18 total)

| Category | Tools |
|----------|-------|
| **R-Map Scanning** | rmap_scan, rmap_service_detect, rmap_os_detect, rmap_comprehensive_scan, rmap_export, rmap_history |
| **Fire Marshal** | fire_marshal_create_investigation, fire_marshal_add_evidence, fire_marshal_trigger_detonator, fire_marshal_close_investigation, fire_marshal_list_investigations, fire_marshal_validate_cryptex |
| **Claude AI** | claude_start_workflow, claude_analyze_scan, claude_compare_scans, claude_escalation_decision, claude_workflow_status, claude_get_events |

### Example Usage

```
User: "Create a Fire Marshal L2 investigation for 192.168.1.0/24
      and run a comprehensive security scan"

Claude: *Autonomously uses these tools:*
  1. fire_marshal_create_investigation → FIRE-20251122-001
  2. claude_start_workflow (network_perimeter)
  3. rmap_comprehensive_scan → scan_id
  4. fire_marshal_add_evidence (links scan)
  5. claude_analyze_scan → AI analysis
  6. fire_marshal_trigger_detonator (vulnerability_assessment)
```

---

## Mode 2: Standalone HTTP API Server

**Best for:** Integration with other tools, REST API access, WebSocket clients

### How It Works

The server runs as a standalone HTTP/WebSocket server on port 8080, providing REST endpoints and real-time event streaming.

### Setup

1. **Create standalone API server binary:**

   Create file: `crates/pyro-claude-integration/src/bin/pyro-api-server.rs`

   ```rust
   //! Standalone HTTP API server (without MCP)

   use pyro_claude_integration::{PyroDatabase, EventBus, ClaudeAgent, FireMarshal};
   use pyro_claude_integration::api::{create_router, AppState};
   use std::sync::Arc;
   use tokio::net::TcpListener;

   #[tokio::main]
   async fn main() {
       tracing_subscriber::fmt::init();

       let db_path = std::env::var("PYRO_DB_PATH")
           .unwrap_or_else(|_| "./pyro_integration.db".to_string());

       let db = Arc::new(PyroDatabase::new(&db_path).expect("Failed to create database"));
       let event_bus = Arc::new(EventBus::new(db.clone(), 1000));
       let claude_agent = Arc::new(ClaudeAgent::new(db.clone(), event_bus.clone()));
       let fire_marshal = Arc::new(FireMarshal::new(db.clone(), event_bus.clone()));

       let state = AppState {
           db,
           event_bus,
           claude_agent,
           fire_marshal,
       };

       let app = create_router(state);

       let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
       println!("🚀 PYRO API Server listening on http://0.0.0.0:8080");
       println!("📊 Health check: http://localhost:8080/health");
       println!("🔌 WebSocket: ws://localhost:8080/ws");
       println!("📖 API Docs: See PYRO_CLAUDE_COMPLETE_INTEGRATION.md");

       axum::serve(listener, app).await.unwrap();
   }
   ```

2. **Build the standalone server:**
   ```bash
   cargo build --release --bin pyro-api-server
   ```

3. **Run the server:**
   ```bash
   export PYRO_DB_PATH=/var/lib/pyro/integration.db
   ./target/release/pyro-api-server
   ```

### REST API Endpoints

```
# Health check
GET http://localhost:8080/health

# Fire Marshal Investigations
POST   /api/v1/investigations              # Create
GET    /api/v1/investigations              # List all
GET    /api/v1/investigations/:id          # Get details
POST   /api/v1/investigations/:id/close    # Close
POST   /api/v1/investigations/:id/evidence # Add evidence
POST   /api/v1/investigations/:id/detonator # Trigger analysis

# Claude Workflows
POST   /api/v1/workflows/start             # Start workflow
GET    /api/v1/workflows/:id/status        # Get status
POST   /api/v1/workflows/analyze           # Analyze scan

# R-Map Scans
GET    /api/v1/scans/:id                   # Get scan results

# WebSocket (real-time events)
WS     ws://localhost:8080/ws
```

### Example API Calls

**Create Investigation:**
```bash
curl -X POST http://localhost:8080/api/v1/investigations \
  -H "Content-Type: application/json" \
  -d '{
    "marshal_level": "L2",
    "subject": "192.168.1.0/24",
    "authorization": "Security Team",
    "legal_review": false
  }'
```

**Start Claude Workflow:**
```bash
curl -X POST http://localhost:8080/api/v1/workflows/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "investigation_id": "uuid-here"
  }'
```

**WebSocket Client (JavaScript):**
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = (event) => {
  const evt = JSON.parse(event.data);
  console.log('Event:', evt.type, evt);
};

// Receive real-time:
// - scan_started
// - scan_progress
// - host_discovered
// - vulnerability_found
// - investigation_created
// - etc.
```

---

## Mode 3: Hybrid Mode (Both!)

Run **both MCP server and HTTP API** simultaneously:

```bash
# Terminal 1: MCP server for Claude integration
export PYRO_DB_PATH=/var/lib/pyro/integration.db
./target/release/pyro-mcp-server  # Runs on stdin/stdout

# Terminal 2: HTTP API for external tools
export PYRO_DB_PATH=/var/lib/pyro/integration.db  # Same database!
./target/release/pyro-api-server   # Runs on port 8080
```

**Benefits:**
- Claude can use MCP tools
- External tools can use REST API
- Both share the same redb database
- Real-time event synchronization via redb event stream

---

## Packaging as Standalone Executable

### Linux

```bash
# Build statically linked binary
cargo build --release --target x86_64-unknown-linux-musl --bin pyro-mcp-server

# Result: Standalone executable with zero dependencies
./target/x86_64-unknown-linux-musl/release/pyro-mcp-server
```

### Windows

```bash
# Build .exe
cargo build --release --bin pyro-mcp-server

# Result: pyro-mcp-server.exe (portable)
target\release\pyro-mcp-server.exe
```

### macOS

```bash
# Build universal binary (Intel + Apple Silicon)
cargo build --release --bin pyro-mcp-server

# Result: Universal macOS executable
./target/release/pyro-mcp-server
```

---

## Distribution

### Create Release Package

```bash
#!/bin/bash
# build-release.sh

VERSION="1.0.0"
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Build
cargo build --release --bin pyro-mcp-server
cargo build --release --bin pyro-api-server

# Create package
mkdir -p "pyro-claude-${VERSION}-${PLATFORM}-${ARCH}"
cp target/release/pyro-mcp-server "pyro-claude-${VERSION}-${PLATFORM}-${ARCH}/"
cp target/release/pyro-api-server "pyro-claude-${VERSION}-${PLATFORM}-${ARCH}/"
cp PYRO_CLAUDE_COMPLETE_INTEGRATION.md "pyro-claude-${VERSION}-${PLATFORM}-${ARCH}/"
cp scripts/setup-pyro-integration.sh "pyro-claude-${VERSION}-${PLATFORM}-${ARCH}/"

# Create tarball
tar czf "pyro-claude-${VERSION}-${PLATFORM}-${ARCH}.tar.gz" \
    "pyro-claude-${VERSION}-${PLATFORM}-${ARCH}"

echo "✅ Release package created: pyro-claude-${VERSION}-${PLATFORM}-${ARCH}.tar.gz"
```

### Install from Package

```bash
tar xzf pyro-claude-1.0.0-linux-x86_64.tar.gz
cd pyro-claude-1.0.0-linux-x86_64

# Install system-wide
sudo cp pyro-mcp-server /usr/local/bin/
sudo cp pyro-api-server /usr/local/bin/

# Or use locally
./pyro-mcp-server  # MCP mode
./pyro-api-server  # HTTP API mode
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PYRO_DB_PATH` | `./pyro_integration.db` | Path to redb database file |
| `RUST_LOG` | `info` | Log level (error, warn, info, debug, trace) |
| `PYRO_API_PORT` | `8080` | HTTP API server port (standalone mode) |

---

## Comparison

| Feature | MCP Mode | HTTP API Mode | Hybrid Mode |
|---------|----------|---------------|-------------|
| **Claude Integration** | ✅ Yes | ❌ No | ✅ Yes |
| **REST API** | ❌ No | ✅ Yes | ✅ Yes |
| **WebSocket Events** | ❌ No | ✅ Yes | ✅ Yes |
| **Autonomous Workflows** | ✅ Yes | ⚠️ Limited | ✅ Yes |
| **External Tool Integration** | ❌ No | ✅ Yes | ✅ Yes |
| **Requires Claude Desktop** | ✅ Yes | ❌ No | ⚠️ Optional |
| **Standalone Deployment** | ✅ Yes | ✅ Yes | ✅ Yes |

---

## Recommendation

**For AI-driven security investigations:** Use **MCP Mode**
- Full Claude autonomy
- Natural language interface
- Automated decision-making

**For tool integration:** Use **HTTP API Mode**
- REST endpoints
- WebSocket streaming
- Language-agnostic

**For maximum flexibility:** Use **Hybrid Mode**
- Best of both worlds
- Shared database
- Unified event system

---

## Troubleshooting

### MCP Mode Issues

**Problem:** MCP server not appearing in Claude
**Solution:**
```bash
# Check MCP config
cat ~/.config/claude/claude_desktop_config.json

# Test server manually
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | \
  ./target/release/pyro-mcp-server
```

### HTTP API Mode Issues

**Problem:** Port 8080 already in use
**Solution:**
```bash
# Use different port
export PYRO_API_PORT=9090
./target/release/pyro-api-server
```

**Problem:** Database permission denied
**Solution:**
```bash
sudo mkdir -p /var/lib/pyro
sudo chown $USER:$USER /var/lib/pyro
```

---

## Next Steps

1. **Choose deployment mode** (MCP, HTTP API, or Hybrid)
2. **Build the binaries** (`cargo build --release`)
3. **Configure environment** (set `PYRO_DB_PATH`)
4. **Start using!**

See **PYRO_CLAUDE_COMPLETE_INTEGRATION.md** for detailed documentation.

---

License: MIT OR Apache-2.0
