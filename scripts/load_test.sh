#!/bin/bash
#
# load_test.sh - Master R-Map load test orchestrator
#
# Usage: ./load_test.sh [scenario1|scenario2|scenario3|scenario4|test]
#
# Orchestrates complete load testing workflow:
#   1. Parse scenario configuration
#   2. Spawn target network
#   3. Start monitoring (Prometheus/Grafana)
#   4. Run R-Map scan with metrics collection
#   5. Generate summary report
#   6. Save results
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
SCENARIOS_CONF="$SCRIPT_DIR/scenarios.conf"
RESULTS_DIR="$PROJECT_ROOT/load-test-results"
RMAP_BINARY="$PROJECT_ROOT/target/release/rmap"

# Current test variables
TEST_TIMESTAMP=""
TEST_DIR=""
TARGETS_FILE=""
METRICS_FILE=""
LOG_FILE=""

# Logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_step() {
    echo -e "\n${CYAN}${BOLD}==>${NC} ${BOLD}$*${NC}\n"
}

# Load scenario configuration
load_scenario() {
    local scenario=$1

    if [[ ! -f "$SCENARIOS_CONF" ]]; then
        log_error "Scenarios configuration not found: $SCENARIOS_CONF"
        exit 1
    fi

    source "$SCENARIOS_CONF"

    # Convert scenario name to uppercase for variable lookup
    local scenario_upper=$(echo "$scenario" | tr '[:lower:]' '[:upper:]')

    # Load scenario variables
    eval "NUM_HOSTS=\${${scenario_upper}_HOSTS:-}"
    eval "PORTS=\${${scenario_upper}_PORTS:-}"
    eval "DESC=\${${scenario_upper}_DESC:-}"
    eval "TIMEOUT=\${${scenario_upper}_TIMEOUT:-2000}"
    eval "CONCURRENCY=\${${scenario_upper}_CONCURRENCY:-1000}"

    if [[ -z "$NUM_HOSTS" ]] || [[ -z "$PORTS" ]]; then
        log_error "Invalid scenario: $scenario"
        echo ""
        echo "Available scenarios:"
        grep "^SCENARIO.*_DESC=" "$SCENARIOS_CONF" | sed 's/SCENARIO/  - scenario/; s/_DESC=/: /'
        exit 1
    fi

    log_info "Scenario: $DESC"
    log_info "Hosts: $NUM_HOSTS"
    log_info "Ports: $PORTS"
    log_info "Timeout: ${TIMEOUT}ms"
    log_info "Concurrency: $CONCURRENCY"
}

# Setup test environment
setup_test_environment() {
    TEST_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    TEST_DIR="$RESULTS_DIR/$TEST_TIMESTAMP"

    log_info "Creating test directory: $TEST_DIR"
    mkdir -p "$TEST_DIR"

    TARGETS_FILE="$TEST_DIR/targets.txt"
    METRICS_FILE="$TEST_DIR/metrics.json"
    LOG_FILE="$TEST_DIR/test.log"

    # Create metadata file
    cat > "$TEST_DIR/metadata.json" << EOF
{
  "timestamp": "$TEST_TIMESTAMP",
  "scenario": "$1",
  "description": "$DESC",
  "num_hosts": $NUM_HOSTS,
  "ports": "$PORTS",
  "timeout_ms": $TIMEOUT,
  "concurrency": $CONCURRENCY
}
EOF

    log_success "Test environment ready"
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites"

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    log_success "Docker found"

    # Check if R-Map is built
    if [[ ! -f "$RMAP_BINARY" ]]; then
        log_warning "R-Map binary not found at $RMAP_BINARY"
        log_info "Building R-Map..."
        cd "$PROJECT_ROOT"
        cargo build --release
        log_success "R-Map built successfully"
    else
        log_success "R-Map binary found"
    fi

    # Check spawn_targets.sh script
    if [[ ! -x "$SCRIPT_DIR/spawn_targets.sh" ]]; then
        log_error "spawn_targets.sh not found or not executable"
        exit 1
    fi
    log_success "spawn_targets.sh found"
}

# Spawn target network
spawn_targets() {
    log_step "Spawning $NUM_HOSTS target hosts"

    local start_time=$(date +%s)

    # Run spawn_targets.sh and save IPs to file
    "$SCRIPT_DIR/spawn_targets.sh" "$NUM_HOSTS" > "$TARGETS_FILE" 2>> "$LOG_FILE"

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    local num_ips=$(wc -l < "$TARGETS_FILE")
    log_success "Spawned $num_ips targets in ${duration}s"

    # Save first 10 IPs for verification
    log_info "Sample targets:"
    head -n 10 "$TARGETS_FILE" | sed 's/^/  /'
    if [[ $num_ips -gt 10 ]]; then
        echo "  ... and $((num_ips - 10)) more"
    fi
}

# Start monitoring
start_monitoring() {
    log_step "Starting monitoring"

    # For now, just log that we would start monitoring
    # In production, this would start Prometheus/Grafana
    log_info "Monitoring: Metrics will be collected during scan"
    log_info "  - Memory usage (RSS, heap)"
    log_info "  - CPU usage (user, system)"
    log_info "  - Network I/O"
    log_info "  - Scan throughput"

    # TODO: Start Prometheus exporter if available
    # TODO: Start Grafana dashboard if available
}

# Run R-Map scan with metrics collection
run_scan() {
    log_step "Running R-Map scan"

    local start_time=$(date +%s)
    local start_time_ns=$(date +%s%N)

    # Prepare R-Map command
    local rmap_cmd=(
        "$RMAP_BINARY"
        --targets "$TARGETS_FILE"
        --ports "$PORTS"
        --timeout "$TIMEOUT"
        --max-connections "$CONCURRENCY"
        --output "$TEST_DIR/results.json"
    )

    log_info "Command: ${rmap_cmd[*]}"

    # Create metrics collection wrapper
    local metrics_script="$TEST_DIR/collect_metrics.sh"
    cat > "$metrics_script" << 'METRICS_EOF'
#!/bin/bash
METRICS_FILE="$1"
SCAN_PID="$2"

echo "[" > "$METRICS_FILE"

first=true
while kill -0 "$SCAN_PID" 2>/dev/null; do
    timestamp=$(date +%s)

    # Collect process metrics
    if [[ -f /proc/$SCAN_PID/status ]]; then
        rss_kb=$(grep VmRSS /proc/$SCAN_PID/status | awk '{print $2}')
        rss_mb=$((rss_kb / 1024))

        # CPU usage
        cpu_times=$(ps -p "$SCAN_PID" -o %cpu,cputime --no-headers)
        cpu_percent=$(echo "$cpu_times" | awk '{print $1}')

        # Network I/O (if available)
        if [[ -f /proc/$SCAN_PID/net/dev ]]; then
            net_rx=$(grep eth0 /proc/$SCAN_PID/net/dev | awk '{print $2}' || echo 0)
            net_tx=$(grep eth0 /proc/$SCAN_PID/net/dev | awk '{print $10}' || echo 0)
        else
            net_rx=0
            net_tx=0
        fi

        # Write metric
        [[ "$first" == "true" ]] || echo "," >> "$METRICS_FILE"
        first=false

        cat >> "$METRICS_FILE" << METRIC_JSON
  {
    "timestamp": $timestamp,
    "memory_mb": $rss_mb,
    "cpu_percent": $cpu_percent,
    "net_rx_bytes": $net_rx,
    "net_tx_bytes": $net_tx
  }
METRIC_JSON
    fi

    sleep 2
done

echo "]" >> "$METRICS_FILE"
METRICS_EOF

    chmod +x "$metrics_script"

    # Run R-Map with metrics collection
    log_info "Starting scan..."
    "${rmap_cmd[@]}" >> "$LOG_FILE" 2>&1 &
    local scan_pid=$!

    # Start metrics collection in background
    "$metrics_script" "$METRICS_FILE" "$scan_pid" &
    local metrics_pid=$!

    # Wait for scan to complete with progress updates
    local last_update=$(date +%s)
    while kill -0 "$scan_pid" 2>/dev/null; do
        sleep 5
        local now=$(date +%s)
        if (( now - last_update >= 30 )); then
            local elapsed=$((now - start_time))
            log_info "Scan in progress... (${elapsed}s elapsed)"
            last_update=$now
        fi
    done

    # Wait for processes to finish
    wait "$scan_pid" || {
        local exit_code=$?
        log_error "R-Map scan failed with exit code: $exit_code"
        kill "$metrics_pid" 2>/dev/null || true
        return 1
    }

    sleep 2  # Give metrics collector time to finish
    kill "$metrics_pid" 2>/dev/null || true

    local end_time=$(date +%s)
    local end_time_ns=$(date +%s%N)
    local duration=$((end_time - start_time))
    local duration_ns=$((end_time_ns - start_time_ns))

    log_success "Scan completed in ${duration}s"

    # Save timing info
    echo "$duration" > "$TEST_DIR/duration.txt"
    echo "$duration_ns" > "$TEST_DIR/duration_ns.txt"
}

# Calculate scan statistics
calculate_statistics() {
    log_step "Calculating statistics"

    # Read metrics
    local duration=$(cat "$TEST_DIR/duration.txt")
    local num_hosts=$(wc -l < "$TARGETS_FILE")

    # Count ports in scan
    local num_ports
    if [[ "$PORTS" =~ - ]]; then
        # Range format (e.g., "1-65535")
        local start_port=$(echo "$PORTS" | cut -d'-' -f1)
        local end_port=$(echo "$PORTS" | cut -d'-' -f2)
        num_ports=$((end_port - start_port + 1))
    else
        # Comma-separated format
        num_ports=$(echo "$PORTS" | tr ',' '\n' | wc -l)
    fi

    local total_checks=$((num_hosts * num_ports))
    local checks_per_sec=$((total_checks / duration))

    # Calculate memory statistics from metrics
    local max_memory=0
    local avg_memory=0
    if [[ -f "$METRICS_FILE" ]]; then
        max_memory=$(jq -r '[.[].memory_mb] | max // 0' "$METRICS_FILE" 2>/dev/null || echo 0)
        avg_memory=$(jq -r '[.[].memory_mb] | add / length // 0' "$METRICS_FILE" 2>/dev/null || echo 0)
    fi

    # Parse results if available
    local open_ports=0
    local closed_ports=0
    local filtered_ports=0
    if [[ -f "$TEST_DIR/results.json" ]]; then
        open_ports=$(jq -r '[.[].ports[]? | select(.state == "open")] | length' "$TEST_DIR/results.json" 2>/dev/null || echo 0)
        closed_ports=$(jq -r '[.[].ports[]? | select(.state == "closed")] | length' "$TEST_DIR/results.json" 2>/dev/null || echo 0)
        filtered_ports=$(jq -r '[.[].ports[]? | select(.state == "filtered")] | length' "$TEST_DIR/results.json" 2>/dev/null || echo 0)
    fi

    # Create statistics JSON
    cat > "$TEST_DIR/statistics.json" << EOF
{
  "duration_seconds": $duration,
  "num_hosts": $num_hosts,
  "num_ports_per_host": $num_ports,
  "total_port_checks": $total_checks,
  "checks_per_second": $checks_per_sec,
  "max_memory_mb": $max_memory,
  "avg_memory_mb": $avg_memory,
  "open_ports": $open_ports,
  "closed_ports": $closed_ports,
  "filtered_ports": $filtered_ports,
  "completion_rate": $(awk "BEGIN {printf \"%.2f\", (($open_ports + $closed_ports + $filtered_ports) / $total_checks) * 100}")
}
EOF

    log_success "Statistics calculated"
}

# Generate summary report
generate_report() {
    log_step "Generating summary report"

    local stats=$(cat "$TEST_DIR/statistics.json")

    # Extract values
    local duration=$(echo "$stats" | jq -r '.duration_seconds')
    local checks_per_sec=$(echo "$stats" | jq -r '.checks_per_second')
    local max_memory=$(echo "$stats" | jq -r '.max_memory_mb')
    local avg_memory=$(echo "$stats" | jq -r '.avg_memory_mb')
    local open_ports=$(echo "$stats" | jq -r '.open_ports')
    local completion_rate=$(echo "$stats" | jq -r '.completion_rate')

    # Create markdown report
    cat > "$TEST_DIR/SUMMARY.md" << EOF
# R-Map Load Test Summary

**Scenario**: $DESC
**Timestamp**: $TEST_TIMESTAMP
**Duration**: ${duration}s

## Configuration

- **Hosts**: $NUM_HOSTS
- **Ports**: $PORTS
- **Timeout**: ${TIMEOUT}ms
- **Concurrency**: $CONCURRENCY

## Performance Metrics

| Metric | Value |
|--------|-------|
| Total Port Checks | $(echo "$stats" | jq -r '.total_port_checks') |
| Checks/Second | ${checks_per_sec} |
| Duration | ${duration}s |
| Completion Rate | ${completion_rate}% |

## Resource Usage

| Resource | Peak | Average |
|----------|------|---------|
| Memory (MB) | ${max_memory} | ${avg_memory} |

## Results

- **Open Ports**: ${open_ports}
- **Closed Ports**: $(echo "$stats" | jq -r '.closed_ports')
- **Filtered Ports**: $(echo "$stats" | jq -r '.filtered_ports')

## Files

- Results: \`results.json\`
- Metrics: \`metrics.json\`
- Logs: \`test.log\`
- Statistics: \`statistics.json\`

## Performance Assessment

EOF

    # Add performance assessment
    if (( checks_per_sec >= 2000 )); then
        echo "✅ **EXCELLENT** - Exceeded stretch goal (>2000 checks/sec)" >> "$TEST_DIR/SUMMARY.md"
    elif (( checks_per_sec >= 500 )); then
        echo "✅ **GOOD** - Met target performance (>500 checks/sec)" >> "$TEST_DIR/SUMMARY.md"
    else
        echo "⚠️  **NEEDS IMPROVEMENT** - Below target (<500 checks/sec)" >> "$TEST_DIR/SUMMARY.md"
    fi

    # Memory assessment
    echo "" >> "$TEST_DIR/SUMMARY.md"
    if (( max_memory < 1024 )); then
        echo "✅ **MEMORY: EXCELLENT** - Under 1GB (stretch goal)" >> "$TEST_DIR/SUMMARY.md"
    elif (( max_memory < 2048 )); then
        echo "✅ **MEMORY: GOOD** - Under 2GB (target)" >> "$TEST_DIR/SUMMARY.md"
    else
        echo "⚠️  **MEMORY: HIGH** - Exceeded 2GB target" >> "$TEST_DIR/SUMMARY.md"
    fi

    log_success "Summary report generated: $TEST_DIR/SUMMARY.md"

    # Create symlink to latest
    ln -sfn "$TEST_DIR" "$RESULTS_DIR/latest"
    log_info "Latest results symlinked to: $RESULTS_DIR/latest"
}

# Display summary
display_summary() {
    echo ""
    echo "=========================================="
    echo "  LOAD TEST COMPLETE"
    echo "=========================================="
    echo ""

    cat "$TEST_DIR/SUMMARY.md" | grep -A 100 "## Performance Metrics"

    echo ""
    echo "Full report: $TEST_DIR/SUMMARY.md"
    echo ""
}

# Cleanup (optional)
cleanup_targets() {
    log_step "Cleaning up test infrastructure"

    if [[ "${CLEANUP:-yes}" == "yes" ]]; then
        "$SCRIPT_DIR/cleanup_targets.sh" >> "$LOG_FILE" 2>&1
        log_success "Cleanup complete"
    else
        log_info "Skipping cleanup (CLEANUP=no)"
        log_info "Run manually: $SCRIPT_DIR/cleanup_targets.sh"
    fi
}

# Main execution
main() {
    echo "=========================================="
    echo "  R-Map Load Testing Framework"
    echo "=========================================="
    echo ""

    if [[ $# -lt 1 ]]; then
        log_error "Usage: $0 <scenario>"
        echo ""
        echo "Available scenarios:"
        if [[ -f "$SCENARIOS_CONF" ]]; then
            grep "^SCENARIO.*_DESC=" "$SCENARIOS_CONF" | sed 's/SCENARIO/  - scenario/; s/_DESC=/: /' | sed 's/SCENARIO_/scenario/g' | tr '[:upper:]' '[:lower:]'
        fi
        echo ""
        echo "Examples:"
        echo "  $0 scenario1    # Wide network scan (10K hosts)"
        echo "  $0 test         # Small test (100 hosts)"
        echo ""
        echo "Environment variables:"
        echo "  CLEANUP=no      Skip cleanup after test"
        exit 1
    fi

    local scenario=$1

    # Load scenario
    load_scenario "$scenario"

    # Setup test environment
    setup_test_environment "$scenario"

    # Redirect all output to log file (while still showing on screen)
    exec > >(tee -a "$LOG_FILE") 2>&1

    # Run test workflow
    check_prerequisites
    spawn_targets
    start_monitoring
    run_scan
    calculate_statistics
    generate_report
    cleanup_targets

    # Display summary
    display_summary

    log_success "All results saved to: $TEST_DIR"
}

main "$@"
