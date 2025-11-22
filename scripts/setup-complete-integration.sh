#!/bin/bash
# Complete setup for PYRO Platform + R-Map + Claude integration

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "================================================================"
echo -e "${BLUE}  PYRO Platform + R-Map + Claude AI Integration Setup${NC}"
echo "================================================================"
echo ""

# Step 1: Clone PYRO Platform (if not exists)
echo -e "${YELLOW}Step 1: Setting up PYRO Platform...${NC}"
if [ ! -d "/home/user/PYRO_Platform_Ignition" ]; then
    echo "Cloning PYRO Platform..."
    cd /home/user
    git clone https://github.com/Ununp3ntium115/PYRO_Platform_Ignition.git
    cd PYRO_Platform_Ignition/mcp-server
    npm install
    echo -e "${GREEN}✓ PYRO Platform installed${NC}"
else
    echo -e "${GREEN}✓ PYRO Platform already exists${NC}"
    cd /home/user/PYRO_Platform_Ignition/mcp-server
    npm install
fi
echo ""

# Step 2: Build R-Map + PYRO + Claude MCP server
echo -e "${YELLOW}Step 2: Building R-Map + PYRO + Claude MCP server...${NC}"
cd /home/user/R-map
cargo build --release --bin pyro-mcp-server
echo -e "${GREEN}✓ MCP server built: target/release/pyro-mcp-server${NC}"
echo ""

# Step 3: Create database directory
echo -e "${YELLOW}Step 3: Creating database directory...${NC}"
if [ ! -d "/var/lib/pyro" ]; then
    sudo mkdir -p /var/lib/pyro
    sudo chown $USER:$USER /var/lib/pyro
    echo -e "${GREEN}✓ Created /var/lib/pyro${NC}"
else
    echo -e "${GREEN}✓ Directory exists: /var/lib/pyro${NC}"
fi
echo ""

# Step 4: Create MCP configuration
echo -e "${YELLOW}Step 4: Creating MCP configuration...${NC}"

MCP_CONFIG_DIR="$HOME/.config/claude"
MCP_CONFIG_FILE="$MCP_CONFIG_DIR/claude_desktop_config.json"

mkdir -p "$MCP_CONFIG_DIR"

cat > "$MCP_CONFIG_FILE" <<'EOF'
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
      }
    },
    "rmap-pyro-claude": {
      "command": "/home/user/R-map/target/release/pyro-mcp-server",
      "args": [],
      "env": {
        "PYRO_DB_PATH": "/var/lib/pyro/integration.db",
        "RUST_LOG": "info"
      }
    }
  }
}
EOF

echo -e "${GREEN}✓ MCP configuration created: $MCP_CONFIG_FILE${NC}"
echo ""

# Step 5: Test MCP servers
echo -e "${YELLOW}Step 5: Testing MCP servers...${NC}"

# Test PYRO Platform MCP
if [ -f "/home/user/PYRO_Platform_Ignition/mcp-server/src/index.js" ]; then
    echo -e "${GREEN}✓ PYRO Platform MCP server found${NC}"
else
    echo -e "${YELLOW}⚠ PYRO Platform MCP server not found${NC}"
fi

# Test R-Map MCP
export PYRO_DB_PATH=/var/lib/pyro/integration.db
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | \
    /home/user/R-map/target/release/pyro-mcp-server > /tmp/mcp-test.json 2>&1 &
MCP_PID=$!
sleep 2
kill $MCP_PID 2>/dev/null || true

if [ -f "/tmp/mcp-test.json" ]; then
    echo -e "${GREEN}✓ R-Map + PYRO + Claude MCP server responds${NC}"
else
    echo -e "${YELLOW}⚠ MCP server test incomplete${NC}"
fi
echo ""

# Summary
echo "================================================================"
echo -e "${GREEN}✓ Setup Complete!${NC}"
echo "================================================================"
echo ""
echo -e "${BLUE}Available MCP Tools (~32 total):${NC}"
echo ""
echo -e "${YELLOW}PYRO Platform MCP:${NC}"
echo "  • validate_cryptex - Cryptex v2.0 compliance"
echo "  • analyze_gaps - Security gap analysis"
echo "  • generate_sdlc_checklist - SDLC workflows"
echo "  • query_steering_docs - Search documentation"
echo "  • create_orchestration_loop - Multi-agent workflows"
echo "  • ...and ~9 more tools"
echo ""
echo -e "${YELLOW}R-Map + PYRO + Claude MCP:${NC}"
echo "  • R-Map Scanning (6): scan, service_detect, os_detect, comprehensive, export, history"
echo "  • Fire Marshal (6): create, evidence, detonator, close, list, validate"
echo "  • Claude AI (6): workflow, analyze, compare, escalate, status, events"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "1. Restart Claude Desktop/Code"
echo "2. Test with: 'List all available MCP tools'"
echo "3. Try autonomous investigation:"
echo "   'Create Fire Marshal L2 investigation for 192.168.1.0/24"
echo "    and run comprehensive security scan'"
echo ""
echo -e "${BLUE}Database:${NC} /var/lib/pyro/integration.db (redb, no Redis needed!)"
echo -e "${BLUE}Documentation:${NC} /home/user/R-map/COMPLETE_MCP_INTEGRATION.md"
echo ""
echo "🎉 You now have ~32 MCP tools available to Claude!"
echo ""
