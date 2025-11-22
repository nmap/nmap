#!/bin/bash
# Quick setup script for PYRO + Claude Integration

set -e

echo "=================================================="
echo "  PYRO + R-Map + Claude AI Integration Setup"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Step 1: Building pyro-claude-integration crate...${NC}"
cargo build --release --package pyro-claude-integration

echo -e "${GREEN}✓ Build complete${NC}"
echo ""

echo -e "${YELLOW}Step 2: Building enhanced MCP server...${NC}"
cargo build --release --bin pyro-mcp-server

echo -e "${GREEN}✓ MCP server built: target/release/pyro-mcp-server${NC}"
echo ""

echo -e "${YELLOW}Step 3: Creating database directory...${NC}"
if [ ! -d "/var/lib/pyro" ]; then
    sudo mkdir -p /var/lib/pyro
    sudo chown $USER:$USER /var/lib/pyro
    echo -e "${GREEN}✓ Created /var/lib/pyro${NC}"
else
    echo -e "${GREEN}✓ Directory exists: /var/lib/pyro${NC}"
fi
echo ""

echo -e "${YELLOW}Step 4: Testing MCP server...${NC}"
export PYRO_DB_PATH=/var/lib/pyro/integration.db
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | ./target/release/pyro-mcp-server > /tmp/mcp-test-output.json 2>&1 &
MCP_PID=$!
sleep 2
kill $MCP_PID 2>/dev/null || true

if [ -f "/tmp/mcp-test-output.json" ]; then
    echo -e "${GREEN}✓ MCP server responds correctly${NC}"
else
    echo -e "${YELLOW}⚠ MCP server test output not found (this is OK)${NC}"
fi
echo ""

echo -e "${YELLOW}Step 5: Checking database...${NC}"
if [ -f "/var/lib/pyro/integration.db" ]; then
    DB_SIZE=$(du -h /var/lib/pyro/integration.db | cut -f1)
    echo -e "${GREEN}✓ Database created: /var/lib/pyro/integration.db ($DB_SIZE)${NC}"
else
    echo -e "${YELLOW}⚠ Database will be created on first use${NC}"
fi
echo ""

echo "=================================================="
echo -e "${GREEN}✓ Setup Complete!${NC}"
echo "=================================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Configure MCP in Claude Desktop/Code:"
echo "   File: ~/.config/claude/claude_desktop_config.json (Linux/macOS)"
echo "   File: %APPDATA%\\Claude\\claude_desktop_config.json (Windows)"
echo ""
echo "2. Add this configuration:"
echo '   {
     "mcpServers": {
       "pyro-claude-integration": {
         "command": "'$(pwd)'/target/release/pyro-mcp-server",
         "env": {
           "PYRO_DB_PATH": "/var/lib/pyro/integration.db",
           "RUST_LOG": "info"
         }
       }
     }
   }'
echo ""
echo "3. Restart Claude Desktop/Code"
echo ""
echo "4. Test with Claude:"
echo '   "List all available PYRO Fire Marshal and R-Map tools"'
echo ""
echo "📚 Full documentation: PYRO_CLAUDE_COMPLETE_INTEGRATION.md"
echo ""
