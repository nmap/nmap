#!/bin/bash
# Quick manual benchmark for testing
# Single iteration comparison between R-Map and nmap

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RMAP_BIN="$SCRIPT_DIR/../../target/release/rmap"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}  R-Map vs nmap Quick Benchmark${NC}"
echo -e "${BLUE}==================================================${NC}"
echo ""

# Check dependencies
if ! command -v nmap &> /dev/null; then
    echo "Error: nmap not found. Install with: sudo apt-get install -y nmap"
    exit 1
fi

if [ ! -f "$RMAP_BIN" ]; then
    echo "Error: R-Map binary not found. Build with: cargo build --release"
    exit 1
fi

# Test target
TARGET="localhost"
PORTS="80,443,3306,6379,5432,8080"

echo "Target: $TARGET"
echo "Ports:  $PORTS"
echo ""

# Test 1: Basic port scan
echo -e "${YELLOW}Test 1: Basic Port Scan${NC}"
echo "----------------------------------------"

echo -n "nmap:  "
NMAP_TIME=$( { time nmap -p "$PORTS" -n -T4 "$TARGET" > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' )
echo "$NMAP_TIME"

echo -n "rmap:  "
RMAP_TIME=$( { time "$RMAP_BIN" -p "$PORTS" -n "$TARGET" > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' )
echo "$RMAP_TIME"

echo ""

# Test 2: Service detection
echo -e "${YELLOW}Test 2: Service Detection${NC}"
echo "----------------------------------------"

echo -n "nmap:  "
NMAP_SV_TIME=$( { time nmap -p "$PORTS" -sV -n -T4 "$TARGET" > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' )
echo "$NMAP_SV_TIME"

echo -n "rmap:  "
RMAP_SV_TIME=$( { time "$RMAP_BIN" -p "$PORTS" -sV -n "$TARGET" > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' )
echo "$RMAP_SV_TIME"

echo ""

# Test 3: Large port range
echo -e "${YELLOW}Test 3: Large Port Range (1-1000)${NC}"
echo "----------------------------------------"

echo -n "nmap:  "
NMAP_RANGE_TIME=$( { time nmap -p 1-1000 -n -T4 "$TARGET" > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' )
echo "$NMAP_RANGE_TIME"

echo -n "rmap:  "
RMAP_RANGE_TIME=$( { time "$RMAP_BIN" -p 1-1000 -n "$TARGET" > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' )
echo "$RMAP_RANGE_TIME"

echo ""
echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}  Quick Benchmark Complete${NC}"
echo -e "${GREEN}==================================================${NC}"
echo ""
echo "Run full benchmark suite with: ./run_benchmarks.sh"
