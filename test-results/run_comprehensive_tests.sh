#!/bin/bash
# Comprehensive R-Map Testing Script
# Agent 4: Testing & Validation Engineer
# Date: 2025-11-19

set -e

RMAP="./target/release/rmap"
RESULTS_DIR="./test-results"
PERF_DIR="$RESULTS_DIR/performance"
FEATURES_DIR="$RESULTS_DIR/features"
BASELINES_DIR="$RESULTS_DIR/baselines"

echo "========================================="
echo "R-Map Comprehensive Testing Suite"
echo "========================================="
echo ""
echo "Test Environment:"
echo "- Binary: $RMAP"
echo "- Version: $(${RMAP} --version 2>&1 || echo 'unknown')"
echo "- Results Directory: $RESULTS_DIR"
echo ""

# Test counter
test_num=1

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local output_file="$3"

    printf "Test %02d: %-50s " $test_num "$test_name"
    test_num=$((test_num + 1))

    if (time eval "$test_cmd") &> "$output_file" 2>&1; then
        echo "✅ PASS"
        return 0
    else
        echo "❌ FAIL"
        return 1
    fi
}

echo "========================================="
echo "PHASE 1: Basic Functionality Tests"
echo "========================================="
echo ""

# Test 1: Help command
run_test "Help command" \
    "$RMAP --help" \
    "$FEATURES_DIR/test-help.txt"

# Test 2: Version command
run_test "Version command" \
    "$RMAP --version" \
    "$FEATURES_DIR/test-version.txt"

echo ""
echo "========================================="
echo "PHASE 2: Scan Type Tests (Localhost)"
echo "========================================="
echo ""

# Test 3: TCP Connect Scan
run_test "TCP Connect Scan (3 ports)" \
    "$RMAP -p 22,80,443 -n --tcp-scan 127.0.0.1" \
    "$PERF_DIR/test-tcp-connect.txt"

# Test 4: Fast Scan
run_test "Fast Scan (top 100 ports)" \
    "$RMAP --fast -n 127.0.0.1" \
    "$PERF_DIR/test-fast-scan.txt"

# Test 5: Quick Scan
run_test "Quick Scan" \
    "$RMAP --quick-scan -n 127.0.0.1" \
    "$PERF_DIR/test-quick-scan.txt"

# Test 6: Port Range Scan
run_test "Port Range Scan (1-100)" \
    "$RMAP -p 1-100 -n 127.0.0.1" \
    "$PERF_DIR/test-port-range.txt"

# Test 7: Multiple Ports
run_test "Multiple Specific Ports" \
    "$RMAP -p 22,80,443,3306,5432,6379,8080,9090 -n 127.0.0.1" \
    "$PERF_DIR/test-multiple-ports.txt"

# Test 8: Web Scan
run_test "Web Scan" \
    "$RMAP --web-scan -n 127.0.0.1" \
    "$PERF_DIR/test-web-scan.txt"

# Test 9: Database Scan
run_test "Database Scan" \
    "$RMAP --database-scan -n 127.0.0.1" \
    "$PERF_DIR/test-database-scan.txt"

echo ""
echo "========================================="
echo "PHASE 3: Output Format Tests"
echo "========================================="
echo ""

# Test 10: JSON Output
run_test "JSON Output Format" \
    "$RMAP -p 80,443 -n --output-json /tmp/rmap-test.json 127.0.0.1" \
    "$FEATURES_DIR/test-json-output.txt"

# Test 11: XML Output
run_test "XML Output Format" \
    "$RMAP -p 80,443 -n --output-xml /tmp/rmap-test.xml 127.0.0.1" \
    "$FEATURES_DIR/test-xml-output.txt"

# Test 12: Grepable Output
run_test "Grepable Output Format" \
    "$RMAP -p 80,443 -n --output-grepable /tmp/rmap-test.gnmap 127.0.0.1" \
    "$FEATURES_DIR/test-grepable-output.txt"

echo ""
echo "========================================="
echo "PHASE 4: Service Detection Tests"
echo "========================================="
echo ""

# Test 13: Service Detection
run_test "Service Detection" \
    "$RMAP -p 22,80,443,3306,5432 -n -sV 127.0.0.1" \
    "$FEATURES_DIR/test-service-detection.txt"

echo ""
echo "========================================="
echo "PHASE 5: Performance Baseline Tests"
echo "========================================="
echo ""

# Test 14: Small port range baseline
run_test "Baseline: 10 ports" \
    "$RMAP -p 1-10 -n 127.0.0.1" \
    "$BASELINES_DIR/baseline-10-ports.txt"

# Test 15: Medium port range baseline
run_test "Baseline: 100 ports" \
    "$RMAP -p 1-100 -n 127.0.0.1" \
    "$BASELINES_DIR/baseline-100-ports.txt"

# Test 16: Large port range baseline
run_test "Baseline: 1000 ports" \
    "$RMAP -p 1-1000 -n 127.0.0.1" \
    "$BASELINES_DIR/baseline-1000-ports.txt"

# Test 17: Very large port range baseline
run_test "Baseline: 10000 ports" \
    "$RMAP -p 1-10000 -n 127.0.0.1" \
    "$BASELINES_DIR/baseline-10000-ports.txt"

echo ""
echo "========================================="
echo "PHASE 6: Advanced Feature Tests"
echo "========================================="
echo ""

# Test 18: Timing options
run_test "Timing: Aggressive (T4)" \
    "$RMAP -p 80,443 -n -T4 127.0.0.1" \
    "$FEATURES_DIR/test-timing-t4.txt"

# Test 19: Multiple targets (if available)
if [ -f "./benchmarks/test-targets/small-network.txt" ]; then
    run_test "Multiple Targets Scan" \
        "$RMAP -p 80,443 -n --fast -iL ./benchmarks/test-targets/small-network.txt" \
        "$FEATURES_DIR/test-multiple-targets.txt"
fi

# Test 20: Verbose output
run_test "Verbose Output" \
    "$RMAP -p 80,443 -n -v 127.0.0.1" \
    "$FEATURES_DIR/test-verbose.txt"

echo ""
echo "========================================="
echo "Test Suite Complete!"
echo "========================================="
echo ""
echo "Results saved to: $RESULTS_DIR"
echo ""

# Count results
passed=$(grep -r "✅ PASS" "$RESULTS_DIR" 2>/dev/null | wc -l || echo 0)
failed=$(grep -r "❌ FAIL" "$RESULTS_DIR" 2>/dev/null | wc -l || echo 0)

echo "Summary:"
echo "  Passed: $passed"
echo "  Failed: $failed"
echo ""

if [ -f "/tmp/rmap-test.json" ]; then
    echo "JSON Output Sample:"
    cat /tmp/rmap-test.json | head -20
fi

exit 0
