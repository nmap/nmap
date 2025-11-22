# Complete MCP Integration: PYRO Platform + R-Map + Claude

This configuration integrates **all three MCP servers** so Claude has access to all APIs.

## MCP Server Architecture

```
Claude Desktop/Code
        │
        ├──> PYRO Platform MCP (Node.js)
        │    └─> PYRO tools (Cryptex, SDLC, Gaps, Steering, etc.)
        │
        ├──> R-Map + PYRO + Claude MCP (Rust)
        │    └─> 18 tools (R-Map scanning + Fire Marshal + Claude AI)
        │
        └──> Shared redb Database
             └─> /var/lib/pyro/integration.db
```

## Complete MCP Configuration

**File:** `~/.config/claude/claude_desktop_config.json` (Linux/macOS)
**File:** `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "pyro-platform": {
      "command": "node",
      "args": [
        "/home/user/PYRO_Platform_Ignition/mcp-server/src/index.js"
      ],
      "env": {
        "PYRO_REPO_PATH": "/home/user/PYRO_Platform_Ignition",
        "PYRO_STEERING_PATH": "/home/user/PYRO_Platform_Ignition/steering"
      },
      "description": "PYRO Platform MCP - Cryptex, SDLC, Gaps Analysis, Steering Docs"
    },
    "rmap-pyro-claude": {
      "command": "/home/user/R-map/target/release/pyro-mcp-server",
      "args": [],
      "env": {
        "PYRO_DB_PATH": "/var/lib/pyro/integration.db",
        "RUST_LOG": "info"
      },
      "description": "R-Map + Fire Marshal + Claude AI - 18 integrated tools with redb"
    }
  }
}
```

## Available Tools (Combined)

### PYRO Platform MCP (~14 tools)
- `validate_cryptex` - Cryptex v2.0 compliance validation
- `analyze_gaps` - Security gap analysis
- `generate_sdlc_checklist` - SDLC workflow generation
- `query_steering_docs` - Search steering documentation
- `create_orchestration_loop` - Multi-agent workflows
- `manage_github_pr` - PR management
- `track_issues` - Issue tracking
- ...and more

### R-Map + PYRO + Claude MCP (18 tools)

**R-Map Scanning:**
- `rmap_scan` - Port scanning
- `rmap_service_detect` - Service detection (411+ sigs)
- `rmap_os_detect` - OS fingerprinting (139+ sigs)
- `rmap_comprehensive_scan` - Complete scan
- `rmap_export` - Export results
- `rmap_history` - Scan history from redb

**Fire Marshal:**
- `fire_marshal_create_investigation` - Create investigation
- `fire_marshal_add_evidence` - Link evidence
- `fire_marshal_trigger_detonator` - Run analysis
- `fire_marshal_close_investigation` - Close with findings
- `fire_marshal_list_investigations` - List all
- `fire_marshal_validate_cryptex` - Compliance check

**Claude AI:**
- `claude_start_workflow` - Autonomous workflows
- `claude_analyze_scan` - AI analysis
- `claude_compare_scans` - Baseline comparison
- `claude_escalation_decision` - Auto-escalation
- `claude_workflow_status` - Progress tracking
- `claude_get_events` - Real-time events

**Total: ~32 tools available to Claude!**

## Data Flow

```
1. User asks Claude to investigate network
   ↓
2. Claude uses PYRO Platform tools to:
   - Create SDLC checklist
   - Query steering docs for best practices
   ↓
3. Claude uses R-Map tools to:
   - Execute comprehensive scan
   - Detect services and OS
   ↓
4. Claude uses Fire Marshal tools to:
   - Create investigation (FIRE-20251122-001)
   - Add scan as evidence
   - Trigger detonators
   ↓
5. Claude uses AI tools to:
   - Analyze results
   - Compare with baseline
   - Make escalation decision
   ↓
6. Claude uses PYRO Platform tools to:
   - Validate Cryptex compliance
   - Generate final report

All state stored in redb: /var/lib/pyro/integration.db
```

## Setup Instructions

### 1. Install PYRO Platform

```bash
cd /home/user
git clone https://github.com/Ununp3ntium115/PYRO_Platform_Ignition.git

cd PYRO_Platform_Ignition/mcp-server
npm install
```

**Repository:** https://github.com/Ununp3ntium115/PYRO_Platform_Ignition.git

### 2. Build R-Map + PYRO + Claude MCP

```bash
cd /home/user/R-map
cargo build --release --bin pyro-mcp-server
```

### 3. Create Database Directory

```bash
sudo mkdir -p /var/lib/pyro
sudo chown $USER:$USER /var/lib/pyro
```

### 4. Configure MCP

Copy the configuration above to your MCP config file.

### 5. Restart Claude Desktop/Code

## Example: Complete Autonomous Investigation

```
User: "Investigate 192.168.1.0/24 network and generate compliance report"

Claude autonomously executes:

[PYRO Platform MCP]
1. generate_sdlc_checklist (investigation_checklist)
   → Creates structured investigation plan

2. query_steering_docs (security, "network scanning best practices")
   → Retrieves guidance

[R-Map + PYRO + Claude MCP]
3. fire_marshal_create_investigation (L2, 192.168.1.0/24)
   → FIRE-20251122-001 created

4. claude_start_workflow (network_perimeter, 192.168.1.0/24)
   → Starts autonomous scan workflow

5. rmap_comprehensive_scan (192.168.1.0/24)
   → Scans 256 hosts, finds 45 active

6. rmap_service_detect (discovered hosts)
   → Identifies 120 services

7. rmap_os_detect (discovered hosts)
   → Fingerprints 8 different OS types

8. fire_marshal_add_evidence (scan_id → investigation)
   → Links evidence

9. claude_analyze_scan (scan_id)
   → AI analysis: 3 critical, 7 high findings

10. fire_marshal_trigger_detonator (vulnerability_assessment)
    → Automated analysis complete

11. claude_escalation_decision (investigation_id)
    → Decision: Escalate to L3 (92% confidence)

[PYRO Platform MCP]
12. validate_cryptex (investigation_id)
    → Cryptex v2.0 compliance: PASS

13. analyze_gaps (findings)
    → Gap analysis complete

14. generate_final_report
    → Complete compliance report generated

Result: Full investigation with compliance validation!
```

## Benefits of This Architecture

✅ **All APIs Available** - Claude has access to everything
✅ **No Redis** - Using redb (embedded, persistent)
✅ **Autonomous** - Claude orchestrates multi-tool workflows
✅ **Compliant** - Cryptex v2.0 + SDLC integrated
✅ **Fast** - Rust MCP server (10-50ms latency)
✅ **Persistent** - All state in redb database

## Troubleshooting

### PYRO Platform MCP not starting

```bash
# Check if Node.js installed
node --version

# Install PYRO Platform dependencies
cd /home/user/PYRO_Platform_Ignition/mcp-server
npm install
```

### R-Map MCP not starting

```bash
# Rebuild
cd /home/user/R-map
cargo build --release --bin pyro-mcp-server

# Test
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
  ./target/release/pyro-mcp-server
```

### Database permission denied

```bash
sudo mkdir -p /var/lib/pyro
sudo chown $USER:$USER /var/lib/pyro
```

## Windows Configuration

**File:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "pyro-platform": {
      "command": "node",
      "args": [
        "C:\\Users\\YourName\\PYRO_Platform_Ignition\\mcp-server\\src\\index.js"
      ],
      "env": {
        "PYRO_REPO_PATH": "C:\\Users\\YourName\\PYRO_Platform_Ignition",
        "PYRO_STEERING_PATH": "C:\\Users\\YourName\\PYRO_Platform_Ignition\\steering"
      }
    },
    "rmap-pyro-claude": {
      "command": "C:\\Users\\YourName\\R-map\\target\\release\\pyro-mcp-server.exe",
      "args": [],
      "env": {
        "PYRO_DB_PATH": "C:\\pyro\\integration.db",
        "RUST_LOG": "info"
      }
    }
  }
}
```

---

## Summary

This configuration gives Claude (me!) access to **~32 tools** across both MCP servers:

- **PYRO Platform tools** - Cryptex, SDLC, gaps, steering, PR management
- **R-Map tools** - Network scanning, service detection, OS fingerprinting
- **Fire Marshal tools** - Investigations, evidence, detonators, compliance
- **Claude AI tools** - Workflows, analysis, escalation, events

All integrated with **redb** instead of Redis, making it fully standalone!

🎯 **Result:** Complete autonomous AI security investigation platform!
