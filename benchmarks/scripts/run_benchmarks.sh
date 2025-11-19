#!/bin/bash
# R-Map vs nmap Comprehensive Benchmark Suite
# This script executes all performance test scenarios and collects detailed metrics

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$BENCHMARK_ROOT/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="$RESULTS_DIR/benchmark_$TIMESTAMP.json"
ITERATIONS=10
WARMUP_RUNS=2

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p "$RESULTS_DIR"

# Logging
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ✅ $*"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ❌ $*"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ⚠️  $*"
}

# Check dependencies
check_dependencies() {
    log "Checking dependencies..."
    
    local deps=("nmap" "docker" "docker-compose" "time" "jq" "python3")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_error "Install with: sudo apt-get install -y ${missing[*]}"
        exit 1
    fi
    
    # Check for R-Map binary
    if [ ! -f "$BENCHMARK_ROOT/../target/release/rmap" ]; then
        log_error "R-Map binary not found. Build with: cargo build --release"
        exit 1
    fi
    
    log_success "All dependencies satisfied"
}

# System preparation
prepare_system() {
    log "Preparing system for benchmarks..."
    
    # Set CPU governor to performance (requires sudo)
    if [ -w /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
        log "Setting CPU governor to performance mode..."
        for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            echo performance > "$cpu" 2>/dev/null || true
        done
    else
        log_warning "Cannot set CPU governor (requires sudo). Results may have higher variance."
    fi
    
    # Clear system caches (requires sudo)
    if [ -w /proc/sys/vm/drop_caches ]; then
        log "Clearing system caches..."
        sync
        echo 3 > /proc/sys/vm/drop_caches
    else
        log_warning "Cannot clear caches (requires sudo). Consider running with sudo."
    fi
    
    log_success "System prepared"
}

# Start Docker test environment
start_docker_services() {
    log "Starting Docker test services..."
    
    cd "$BENCHMARK_ROOT/../tests/integration"
    
    # Stop any existing containers
    docker-compose down -v &> /dev/null || true
    
    # Start fresh containers
    docker-compose up -d
    
    # Wait for services to be healthy
    log "Waiting for services to become healthy (30s)..."
    sleep 30
    
    # Verify services are running
    local running=$(docker-compose ps --services --filter "status=running" | wc -l)
    log "Running services: $running"
    
    if [ "$running" -lt 5 ]; then
        log_error "Not enough services running. Check Docker Compose logs."
        exit 1
    fi
    
    log_success "Docker services started successfully"
    
    cd "$SCRIPT_DIR"
}

# Run a single benchmark iteration
run_single_benchmark() {
    local tool=$1
    local target=$2
    local flags=$3
    local run_number=$4
    local scenario_name=$5
    
    local output_file="$RESULTS_DIR/tmp_${scenario_name}_${tool}_run${run_number}.json"
    local time_file="$RESULTS_DIR/tmp_${scenario_name}_${tool}_run${run_number}_time.txt"
    
    # Clear DNS cache if possible
    systemd-resolve --flush-caches &> /dev/null || true
    
    # Run benchmark with time measurement
    if [ "$tool" = "nmap" ]; then
        /usr/bin/time -v nmap $flags $target -oX "$output_file" 2> "$time_file" > /dev/null
    else
        /usr/bin/time -v "$BENCHMARK_ROOT/../target/release/rmap" $flags $target --format json --output "$output_file" 2> "$time_file" > /dev/null
    fi
    
    # Extract timing from /usr/bin/time output
    local elapsed=$(grep "Elapsed" "$time_file" | awk '{print $8}')
    local max_rss=$(grep "Maximum resident set size" "$time_file" | awk '{print $6}')
    local cpu_percent=$(grep "Percent of CPU" "$time_file" | awk '{print $7}' | tr -d '%')
    
    echo "$elapsed|$max_rss|$cpu_percent"
}

# Run benchmark scenario
run_scenario() {
    local scenario_id=$1
    local scenario_name=$2
    local rmap_cmd=$3
    local nmap_cmd=$4
    
    log "Running scenario $scenario_id: $scenario_name"
    
    local rmap_times=()
    local rmap_memory=()
    local rmap_cpu=()
    
    local nmap_times=()
    local nmap_memory=()
    local nmap_cpu=()
    
    # Warmup runs (discard results)
    log "  Warmup runs ($WARMUP_RUNS iterations)..."
    for i in $(seq 1 $WARMUP_RUNS); do
        run_single_benchmark "nmap" "localhost" "$nmap_cmd" "warmup_$i" "$scenario_id" > /dev/null
        sleep 2
        run_single_benchmark "rmap" "localhost" "$rmap_cmd" "warmup_$i" "$scenario_id" > /dev/null
        sleep 2
    done
    
    # Actual benchmark runs
    log "  Benchmark runs ($ITERATIONS iterations)..."
    for i in $(seq 1 $ITERATIONS); do
        echo -n "    Run $i/$ITERATIONS: "
        
        # Run nmap
        local nmap_result=$(run_single_benchmark "nmap" "localhost" "$nmap_cmd" "$i" "$scenario_id")
        IFS='|' read -r elapsed_nmap mem_nmap cpu_nmap <<< "$nmap_result"
        nmap_times+=("$elapsed_nmap")
        nmap_memory+=("$mem_nmap")
        nmap_cpu+=("$cpu_nmap")
        
        sleep 3
        
        # Run rmap
        local rmap_result=$(run_single_benchmark "rmap" "localhost" "$rmap_cmd" "$i" "$scenario_id")
        IFS='|' read -r elapsed_rmap mem_rmap cpu_rmap <<< "$rmap_result"
        rmap_times+=("$elapsed_rmap")
        rmap_memory+=("$mem_rmap")
        rmap_cpu+=("$cpu_rmap")
        
        echo "nmap: ${elapsed_nmap}s, rmap: ${elapsed_rmap}s"
        
        sleep 3
    done
    
    # Calculate statistics
    local nmap_median=$(python3 -c "import statistics; print(statistics.median([${nmap_times[*]/%/,}]))" 2>/dev/null || echo "0")
    local rmap_median=$(python3 -c "import statistics; print(statistics.median([${rmap_times[*]/%/,}]))" 2>/dev/null || echo "0")
    
    log_success "  Completed: nmap median=${nmap_median}s, rmap median=${rmap_median}s"
    
    # Store results in JSON
    cat >> "$RESULTS_FILE" << EOF
  {
    "scenario_id": "$scenario_id",
    "scenario_name": "$scenario_name",
    "nmap_command": "$nmap_cmd",
    "rmap_command": "$rmap_cmd",
    "iterations": $ITERATIONS,
    "nmap_times": [${nmap_times[*]/%/,}],
    "rmap_times": [${rmap_times[*]/%/,}],
    "nmap_memory_kb": [${nmap_memory[*]/%/,}],
    "rmap_memory_kb": [${rmap_memory[*]/%/,}],
    "nmap_cpu_percent": [${nmap_cpu[*]/%/,}],
    "rmap_cpu_percent": [${rmap_cpu[*]/%/,}]
  },
EOF
}

# Main benchmark execution
main() {
    log "Starting R-Map vs nmap Performance Benchmarks"
    log "Timestamp: $TIMESTAMP"
    log "Results will be saved to: $RESULTS_FILE"
    echo ""
    
    check_dependencies
    prepare_system
    start_docker_services
    
    # Initialize results JSON
    cat > "$RESULTS_FILE" << EOF
{
  "benchmark_metadata": {
    "timestamp": "$TIMESTAMP",
    "rmap_version": "$(cd $BENCHMARK_ROOT/.. && git describe --tags --always 2>/dev/null || echo 'unknown')",
    "nmap_version": "$(nmap --version | head -n1 | awk '{print $3}')",
    "hostname": "$(hostname)",
    "kernel": "$(uname -r)",
    "cpu_count": "$(nproc)"
  },
  "scenarios": [
EOF
    
    # Test Scenarios
    log ""
    log "================================================"
    log "TEST SCENARIOS"
    log "================================================"
    
    # TC-001: Single Host, Top 100 Ports
    run_scenario "TC-001" \
                "Single Host, Top 100 Ports" \
                "--fast -n" \
                "--top-ports 100 -n -T4"
    
    # TC-002: Single Host, Custom Ports
    run_scenario "TC-002" \
                "Single Host, Custom Ports (22,80,443,3306,6379,5432)" \
                "-p 22,80,443,3306,6379,5432 -n" \
                "-p 22,80,443,3306,6379,5432 -n -T4"
    
    # TC-003: Single Host, Service Detection
    run_scenario "TC-003" \
                "Single Host, Service Detection" \
                "-p 8080,2222,21,3306,6379,5432 -sV -n" \
                "-p 8080,2222,21,3306,6379,5432 -sV -n -T4"
    
    # TC-004: Single Host, Large Port Range
    run_scenario "TC-004" \
                "Single Host, Large Port Range (1-1000)" \
                "-p 1-1000 -n" \
                "-p 1-1000 -n -T4"
    
    # TC-005: Single Host, All Common Ports
    run_scenario "TC-005" \
                "Single Host, All Common Ports (1-10000)" \
                "-p 1-10000 -n" \
                "-p 1-10000 -n -T4"

    # TC-006: Small Network Sweep (/24)
    run_scenario "TC-006" \
                "Small Network, Top 100 Ports (10 hosts)" \
                "--fast -n -iL $BENCHMARK_ROOT/test-targets/small-network.txt" \
                "--top-ports 100 -n -T4 -iL $BENCHMARK_ROOT/test-targets/small-network.txt"

    # TC-007: Small Network with Service Detection
    run_scenario "TC-007" \
                "Small Network, Service Detection (10 hosts)" \
                "-p 22,80,443,3306,6379,5432 -sV -n -iL $BENCHMARK_ROOT/test-targets/small-network.txt" \
                "-p 22,80,443,3306,6379,5432 -sV -n -T4 -iL $BENCHMARK_ROOT/test-targets/small-network.txt"

    # TC-008: Medium Network Fast Scan
    run_scenario "TC-008" \
                "Medium Network, Fast Scan (100 hosts)" \
                "--fast -n -iL $BENCHMARK_ROOT/test-targets/medium-network.txt" \
                "--top-ports 100 -n -T4 -iL $BENCHMARK_ROOT/test-targets/medium-network.txt"

    # TC-009: Stress Test - Large Port Range on Multiple Hosts
    run_scenario "TC-009" \
                "Stress Test, Large Port Range (10 hosts, 1-1000)" \
                "-p 1-1000 -n -iL $BENCHMARK_ROOT/test-targets/small-network.txt" \
                "-p 1-1000 -n -T4 -iL $BENCHMARK_ROOT/test-targets/small-network.txt"

    # TC-010: Large Network Sweep (simulated CIDR)
    run_scenario "TC-010" \
                "Large Network, Fast Scan (1000 hosts)" \
                "--fast -n -iL $BENCHMARK_ROOT/test-targets/large-network.txt" \
                "--top-ports 100 -n -T4 -iL $BENCHMARK_ROOT/test-targets/large-network.txt"

    # Close JSON
    # Remove trailing comma from last scenario
    sed -i '$ s/,$//' "$RESULTS_FILE"
    
    cat >> "$RESULTS_FILE" << EOF
  ]
}
EOF
    
    log ""
    log "================================================"
    log "BENCHMARK COMPLETE"
    log "================================================"
    log_success "Results saved to: $RESULTS_FILE"
    
    # Cleanup temporary files
    rm -f "$RESULTS_DIR"/tmp_*.json "$RESULTS_DIR"/tmp_*.txt
    
    # Generate summary
    log ""
    log "Generating summary report..."
    python3 "$SCRIPT_DIR/analyze_results.py" "$RESULTS_FILE"
    
    log ""
    log_success "Benchmark suite completed successfully!"
}

# Run main
main "$@"
