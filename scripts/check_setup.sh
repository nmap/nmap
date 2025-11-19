#!/bin/bash
#
# check_setup.sh - Verify R-Map load testing environment
#
# Usage: ./check_setup.sh
#
# Checks all prerequisites and reports setup status
#

set -eo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

checks_passed=0
checks_failed=0

check_pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    ((checks_passed++))
}

check_fail() {
    echo -e "  ${RED}✗${NC} $1"
    ((checks_failed++))
}

check_warn() {
    echo -e "  ${YELLOW}!${NC} $1"
}

echo "=========================================="
echo "  R-Map Load Testing Setup Verification"
echo "=========================================="
echo ""

# Check 1: Docker
echo "${BLUE}[1/7]${NC} Checking Docker..."
if command -v docker &> /dev/null; then
    check_pass "Docker installed: $(docker --version | head -1)"

    if docker info &> /dev/null 2>&1; then
        check_pass "Docker daemon running"
    else
        check_fail "Docker daemon not accessible (try: sudo usermod -aG docker \$USER)"
        check_warn "You may need to logout and login for group changes"
    fi
else
    check_fail "Docker not installed"
    check_warn "Install: curl -fsSL https://get.docker.com | sh"
fi
echo ""

# Check 2: jq
echo "${BLUE}[2/7]${NC} Checking jq (JSON processor)..."
if command -v jq &> /dev/null; then
    check_pass "jq installed: $(jq --version)"
else
    check_fail "jq not installed"
    check_warn "Install: sudo apt install jq -y"
fi
echo ""

# Check 3: R-Map binary
echo "${BLUE}[3/7]${NC} Checking R-Map binary..."
if [[ -f "$PROJECT_ROOT/target/release/rmap" ]]; then
    check_pass "R-Map binary found: $PROJECT_ROOT/target/release/rmap"

    size=$(du -h "$PROJECT_ROOT/target/release/rmap" | cut -f1)
    check_pass "Binary size: $size"
else
    check_fail "R-Map binary not found"
    check_warn "Build: cd $PROJECT_ROOT && cargo build --release"
fi
echo ""

# Check 4: Scripts
echo "${BLUE}[4/7]${NC} Checking load test scripts..."
for script in spawn_targets.sh load_test.sh cleanup_targets.sh; do
    if [[ -x "$SCRIPT_DIR/$script" ]]; then
        check_pass "$script is executable"
    else
        check_fail "$script not found or not executable"
        check_warn "Run: chmod +x $SCRIPT_DIR/*.sh"
    fi
done
echo ""

# Check 5: Configuration
echo "${BLUE}[5/7]${NC} Checking configuration..."
if [[ -f "$SCRIPT_DIR/scenarios.conf" ]]; then
    check_pass "scenarios.conf found"

    # Source and verify
    if source "$SCRIPT_DIR/scenarios.conf" 2>/dev/null; then
        check_pass "Configuration valid"

        # Count scenarios
        scenario_count=$(grep -c "^SCENARIO.*_HOSTS=" "$SCRIPT_DIR/scenarios.conf" || echo 0)
        check_pass "$scenario_count scenarios configured"
    else
        check_fail "Configuration has syntax errors"
    fi
else
    check_fail "scenarios.conf not found"
fi
echo ""

# Check 6: Documentation
echo "${BLUE}[6/7]${NC} Checking documentation..."
for doc in README.md QUICKSTART.md; do
    if [[ -f "$SCRIPT_DIR/$doc" ]]; then
        check_pass "$doc available"
    else
        check_warn "$doc not found (optional)"
    fi
done
echo ""

# Check 7: System Resources
echo "${BLUE}[7/7]${NC} Checking system resources..."

# Available memory
if command -v free &> /dev/null; then
    mem_gb=$(free -g | awk '/^Mem:/{print $2}')
    if (( mem_gb >= 4 )); then
        check_pass "Available RAM: ${mem_gb}GB (sufficient for medium tests)"
    elif (( mem_gb >= 2 )); then
        check_pass "Available RAM: ${mem_gb}GB (sufficient for small tests)"
        check_warn "For large tests (>10K hosts), 8GB+ recommended"
    else
        check_warn "Available RAM: ${mem_gb}GB (may limit test scale)"
    fi
fi

# Disk space
if command -v df &> /dev/null; then
    disk_gb=$(df -BG "$PROJECT_ROOT" | awk 'NR==2{print $4}' | sed 's/G//')
    if (( disk_gb >= 10 )); then
        check_pass "Free disk space: ${disk_gb}GB (sufficient)"
    else
        check_warn "Free disk space: ${disk_gb}GB (may fill up with large tests)"
    fi
fi

# CPU cores
if [[ -f /proc/cpuinfo ]]; then
    cpu_cores=$(grep -c ^processor /proc/cpuinfo)
    check_pass "CPU cores: $cpu_cores"
fi

echo ""
echo "=========================================="
echo "  Summary"
echo "=========================================="
echo ""
echo -e "${GREEN}Passed: $checks_passed${NC}"
echo -e "${RED}Failed: $checks_failed${NC}"
echo ""

if (( checks_failed == 0 )); then
    echo -e "${GREEN}✓ Setup complete! Ready to run load tests.${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Run small test: ./load_test.sh test"
    echo "  2. View results: cat ../load-test-results/latest/SUMMARY.md"
    echo "  3. Scale up: ./load_test.sh scenario1"
    echo ""
    echo "Documentation: ./README.md"
    exit 0
else
    echo -e "${YELLOW}⚠ Setup incomplete. Fix the failed checks above.${NC}"
    echo ""
    echo "Quick fixes:"
    echo "  - Install Docker: curl -fsSL https://get.docker.com | sh"
    echo "  - Install jq: sudo apt install jq -y"
    echo "  - Build R-Map: cd $PROJECT_ROOT && cargo build --release"
    echo "  - Fix permissions: chmod +x $SCRIPT_DIR/*.sh"
    echo ""
    exit 1
fi
