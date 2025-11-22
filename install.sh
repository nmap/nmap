#!/usr/bin/env bash
# R-Map Universal Installer
# Supports Linux, macOS, WSL
# Installs R-Map standalone binary + MCP server + Web UI

set -euo pipefail

echo ""
echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
echo "┃  R-Map Universal Installer v1.0.0      ┃"
echo "┃  Rust + redb + Svelte Network Scanner  ┃"
echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        OS="windows"
    else
        print_error "Unsupported OS: $OSTYPE"
        exit 1
    fi
    print_success "Detected OS: $OS"
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    print_success "Detected architecture: $ARCH"
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."

    # Check Rust
    if command -v cargo &> /dev/null; then
        RUST_VERSION=$(rustc --version | awk '{print $2}')
        print_success "Rust installed: $RUST_VERSION"
        HAS_RUST=true
    else
        print_warning "Rust not installed - will use pre-built binary"
        HAS_RUST=false
    fi

    # Check Node.js (for web UI)
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version)
        print_success "Node.js installed: $NODE_VERSION"
        HAS_NODE=true
    else
        print_warning "Node.js not installed - web UI will not be available"
        HAS_NODE=false
    fi

    # Check Docker (optional)
    if command -v docker &> /dev/null; then
        print_success "Docker installed"
        HAS_DOCKER=true
    else
        print_info "Docker not installed (optional)"
        HAS_DOCKER=false
    fi
}

# Install from source
install_from_source() {
    print_info "Building from source..."

    # Build R-Map standalone binary
    print_info "Building rmap binary..."
    cargo build --release --bin rmap
    print_success "Built rmap binary"

    # Build MCP server
    print_info "Building rmap-mcp-server..."
    cargo build --release --bin rmap-mcp-server
    print_success "Built rmap-mcp-server"

    # Install to /usr/local/bin
    print_info "Installing binaries..."
    sudo cp target/release/rmap /usr/local/bin/
    sudo cp target/release/rmap-mcp-server /usr/local/bin/
    sudo chmod +x /usr/local/bin/rmap
    sudo chmod +x /usr/local/bin/rmap-mcp-server

    print_success "Binaries installed to /usr/local/bin"
}

# Create data directories
create_directories() {
    print_info "Creating data directories..."

    # Create /var/lib/rmap for database
    if [ "$OS" != "macos" ]; then
        sudo mkdir -p /var/lib/rmap
        sudo chown $USER:$USER /var/lib/rmap
    else
        mkdir -p ~/Library/Application\ Support/rmap
    fi

    # Create /etc/rmap for config
    if [ "$OS" != "macos" ]; then
        sudo mkdir -p /etc/rmap
        sudo chown $USER:$USER /etc/rmap
    else
        mkdir -p ~/.rmap
    fi

    print_success "Directories created"
}

# Install web UI
install_web_ui() {
    if [ "$HAS_NODE" = true ]; then
        print_info "Installing web UI dependencies..."

        cd frontend-svelte
        npm install
        print_success "Web UI dependencies installed"

        print_info "Building web UI..."
        npm run build
        print_success "Web UI built"
        cd ..
    else
        print_warning "Skipping web UI (Node.js not installed)"
    fi
}

# Create configuration
create_config() {
    print_info "Creating configuration..."

    if [ "$OS" != "macos" ]; then
        CONFIG_DIR="/etc/rmap"
    else
        CONFIG_DIR="$HOME/.rmap"
    fi

    # Create default config
    cat > "$CONFIG_DIR/config.toml" <<EOF
# R-Map Configuration

[database]
path = "/var/lib/rmap/scans.db"  # macOS: ~/Library/Application Support/rmap/scans.db

[logging]
level = "info"

[scanner]
default_timing = "normal"
max_concurrent = 100
timeout = 300

[mcp_server]
bind = "stdio"  # MCP protocol over stdio
EOF

    print_success "Configuration created: $CONFIG_DIR/config.toml"
}

# Print installation summary
print_summary() {
    echo ""
    echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
    echo "┃  Installation Complete! 🎉              ┃"
    echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
    echo ""

    print_success "R-Map is now installed!"
    echo ""

    echo "📦 Installed Components:"
    echo "  • rmap (standalone binary)"
    echo "  • rmap-mcp-server (MCP protocol server)"
    if [ "$HAS_NODE" = true ]; then
        echo "  • Web UI (Svelte frontend)"
    fi
    echo ""

    echo "🚀 Quick Start:"
    echo "  # Standalone scanner"
    echo "  rmap example.com -p 80,443"
    echo ""
    echo "  # MCP server"
    echo "  rmap-mcp-server"
    echo ""
    if [ "$HAS_NODE" = true ]; then
        echo "  # Web UI"
        echo "  cd frontend-svelte && npm run dev"
        echo "  # Open http://localhost:5173"
        echo ""
    fi

    echo "📚 Documentation:"
    echo "  • README.md - General overview"
    echo "  • PYRO_INTEGRATION.md - Fire Marshal integration"
    echo "  • GitHub: https://github.com/Ununp3ntium115/R-map"
    echo ""

    echo "🔐 Permissions:"
    echo "  • For SYN scans (requires root):"
    echo "    sudo setcap cap_net_raw+ep /usr/local/bin/rmap"
    echo "  • For connect scans (no root required):"
    echo "    rmap <target> -sT  # Use -sT flag"
    echo ""

    if [ "$OS" != "macos" ]; then
        DB_PATH="/var/lib/rmap/scans.db"
        CONFIG_PATH="/etc/rmap/config.toml"
    else
        DB_PATH="~/Library/Application Support/rmap/scans.db"
        CONFIG_PATH="~/.rmap/config.toml"
    fi

    echo "📁 File Locations:"
    echo "  • Binaries: /usr/local/bin/rmap{,-mcp-server}"
    echo "  • Database: $DB_PATH"
    echo "  • Config: $CONFIG_PATH"
    echo ""
}

# Main installation flow
main() {
    detect_os
    detect_arch
    check_prerequisites

    if [ "$HAS_RUST" = true ]; then
        install_from_source
    else
        print_error "Rust required for installation. Install from https://rustup.rs"
        exit 1
    fi

    create_directories
    install_web_ui
    create_config
    print_summary
}

# Run installer
main
