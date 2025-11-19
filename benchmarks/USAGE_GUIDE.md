# R-Map Benchmarking Suite - Usage Guide

Complete guide for running performance benchmarks and analyzing results.

## Quick Start

### 1. Prerequisites

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y nmap sysstat time jq docker.io docker-compose python3 python3-pip

# Build R-Map in release mode
cd /home/user/R-map
cargo build --release

# Verify binary exists
ls -lh target/release/rmap
```

### 2. Run Your First Benchmark

```bash
# Navigate to benchmarks directory
cd /home/user/R-map/benchmarks/scripts

# Run a quick single-iteration test
./quick_benchmark.sh

# Run full benchmark suite (10 iterations per scenario)
./run_benchmarks.sh
```

### 3. Analyze Results

```bash
# Results are saved to benchmarks/results/
ls -lth /home/user/R-map/benchmarks/results/

# Analyze the latest results
python3 analyze_results.py ../results/benchmark_*.json

# View the generated report
cat ../results/SUMMARY_*.md
```

## Detailed Workflows

### Workflow 1: Development Testing

Quick validation during development:

```bash
cd /home/user/R-map/benchmarks/scripts

# Build latest code
cd /home/user/R-map && cargo build --release && cd benchmarks/scripts

# Quick test (1 iteration, subset of scenarios)
./quick_benchmark.sh

# Review results
cat ../results/quick_benchmark_*.txt
```

### Workflow 2: Pre-Commit Validation

Before committing performance-related changes:

```bash
cd /home/user/R-map/benchmarks/scripts

# Run full benchmark suite
./run_benchmarks.sh

# Check for regressions against baseline
python3 compare_baseline.py \
  ../results/benchmark_$(date +%Y%m%d)*.json \
  ../baseline/baseline.json

# If no regressions, commit is safe
echo $?  # 0 = pass, 1 = regression detected
```

### Workflow 3: Establishing Baseline

After major milestone or release:

```bash
cd /home/user/R-map/benchmarks/scripts

# Run benchmarks 3 times for consistency
./run_benchmarks.sh  # Run 1
sleep 60
./run_benchmarks.sh  # Run 2
sleep 60
./run_benchmarks.sh  # Run 3

# Review all results
ls -lth ../results/

# Choose best result as baseline
cp ../results/benchmark_20241118_140530.json ../baseline/baseline.json

# Commit baseline to repository
git add ../baseline/baseline.json
git commit -m "chore: Establish performance baseline v1.0"
```

### Workflow 4: Performance Optimization

Iterative optimization workflow:

```bash
# 1. Establish baseline
cd /home/user/R-map/benchmarks/scripts
./run_benchmarks.sh
cp ../results/benchmark_*.json ../baseline/before_optimization.json

# 2. Make code changes
cd /home/user/R-map
# ... edit code ...
cargo build --release

# 3. Run benchmarks again
cd benchmarks/scripts
./run_benchmarks.sh

# 4. Compare results
python3 compare_baseline.py \
  ../results/benchmark_*.json \
  ../baseline/before_optimization.json

# 5. Review detailed analysis
cat ../results/SUMMARY_*.md

# 6. Iterate until satisfied
```

### Workflow 5: Regression Investigation

When CI detects a regression:

```bash
# 1. Reproduce locally
cd /home/user/R-map/benchmarks/scripts
./run_benchmarks.sh

# 2. Compare with baseline
python3 compare_baseline.py \
  ../results/benchmark_latest.json \
  ../baseline/baseline.json

# 3. Identify problematic scenarios
# Look for scenarios marked with ❌ REGRESSION

# 4. Run specific scenario manually for debugging
cd /home/user/R-map
/usr/bin/time -v ./target/release/rmap -p 1-1000 -n localhost

# 5. Profile the slow path
# Use perf, flamegraph, or other profiling tools

# 6. Fix and retest
cargo build --release
cd benchmarks/scripts
./run_benchmarks.sh
```

## Test Scenarios Reference

### TC-001: Single Host, Top 100 Ports
- **Complexity:** Low
- **Duration:** ~30s
- **Purpose:** Basic performance, startup overhead
- **Command:** `rmap --fast -n localhost`

### TC-002: Single Host, Custom Ports
- **Complexity:** Low
- **Duration:** ~30s
- **Purpose:** Specific port targeting
- **Command:** `rmap -p 22,80,443,3306,6379,5432 -n localhost`

### TC-003: Single Host, Service Detection
- **Complexity:** Medium
- **Duration:** ~60s
- **Purpose:** Service fingerprinting performance
- **Command:** `rmap -p 8080,2222,21,3306,6379,5432 -sV -n localhost`

### TC-004: Single Host, Large Port Range
- **Complexity:** Medium
- **Duration:** ~90s
- **Purpose:** Port scanning throughput
- **Command:** `rmap -p 1-1000 -n localhost`

### TC-005: Single Host, Extended Range
- **Complexity:** High
- **Duration:** ~120s
- **Purpose:** Extended port coverage
- **Command:** `rmap -p 1-10000 -n localhost`

### TC-006: Small Network, Fast Scan
- **Complexity:** High
- **Duration:** ~5min
- **Purpose:** Multi-host parallelization
- **Command:** `rmap --fast -n -iL test-targets/small-network.txt`

### TC-007: Small Network, Service Detection
- **Complexity:** Very High
- **Duration:** ~10min
- **Purpose:** Service detection across network
- **Command:** `rmap -p 22,80,443,3306,6379,5432 -sV -n -iL test-targets/small-network.txt`

### TC-008: Medium Network, Fast Scan
- **Complexity:** High
- **Duration:** ~10min
- **Purpose:** 100-host scalability
- **Command:** `rmap --fast -n -iL test-targets/medium-network.txt`

### TC-009: Stress Test
- **Complexity:** Very High
- **Duration:** ~15min
- **Purpose:** Combined load (many hosts × large port range)
- **Command:** `rmap -p 1-1000 -n -iL test-targets/small-network.txt`

### TC-010: Large Network Sweep
- **Complexity:** Very High
- **Duration:** ~30min
- **Purpose:** Maximum scalability (1000 hosts)
- **Command:** `rmap --fast -n -iL test-targets/large-network.txt`

## Understanding Results

### Metrics Explained

**Time Metrics:**
- **Median Time:** Middle value across 10 runs (most representative)
- **P95 Time:** 95th percentile (worst-case excluding outliers)
- **P99 Time:** 99th percentile (near worst-case)

**Memory Metrics:**
- **Peak Memory:** Maximum RSS (Resident Set Size) in KB
- **Reported in MB** for readability

**CPU Metrics:**
- **CPU Usage:** Percentage of CPU time used
- Higher is better for compute-bound tasks

**Performance Comparison:**
- **Time Difference:** `(rmap - nmap) / nmap * 100%`
  - Negative = R-Map faster
  - Positive = nmap faster
- **Memory Difference:** Same formula
  - Negative = R-Map uses less memory
  - Positive = nmap uses less memory

### Pass/Fail Criteria

**PASS Conditions:**
- Time within ±20% of nmap
- Memory within ±20% of nmap

**REGRESSION Conditions:**
- Time >10% slower than baseline
- Memory >15% higher than baseline

### Reading Console Output

```
✅ TC-001: Single Host, Top 100 Ports
   Time:   nmap=2.45s, rmap=2.31s (-5.7%)
   Memory: nmap=15.2MB, rmap=14.1MB (-7.2%)
```

- ✅ = Scenario passed
- ❌ = Scenario failed
- ⚠️ = Warning/new scenario
- Negative percentages = R-Map better
- Positive percentages = nmap better

### Reading Markdown Reports

Generated reports include:
1. **Executive Summary:** Overall pass rate and key findings
2. **Detailed Results:** Per-scenario breakdowns
3. **Recommendations:** Actionable next steps

Location: `/home/user/R-map/benchmarks/results/SUMMARY_*.md`

## Customization

### Running Specific Scenarios

Edit `run_benchmarks.sh` to comment out unwanted scenarios:

```bash
# Comment out to skip
# run_scenario "TC-010" ...

# Keep only the scenarios you need
run_scenario "TC-001" ...
run_scenario "TC-002" ...
```

### Adjusting Iterations

Edit `run_benchmarks.sh`:

```bash
ITERATIONS=10      # Change to 5 for faster testing
WARMUP_RUNS=2      # Change to 1 or 0 to skip warmup
```

### Custom Test Targets

Create your own target file:

```bash
echo "192.168.1.100" > /home/user/R-map/benchmarks/test-targets/my-targets.txt
echo "192.168.1.101" >> /home/user/R-map/benchmarks/test-targets/my-targets.txt

# Use in custom scenario
run_scenario "TC-CUSTOM" \
            "My Custom Test" \
            "--fast -n -iL $BENCHMARK_ROOT/test-targets/my-targets.txt" \
            "--top-ports 100 -n -T4 -iL $BENCHMARK_ROOT/test-targets/my-targets.txt"
```

### Output Formats

All results are saved as JSON for custom analysis:

```bash
# Pretty-print results
jq . /home/user/R-map/benchmarks/results/benchmark_*.json

# Extract specific scenario
jq '.scenarios[] | select(.scenario_id == "TC-001")' results.json

# Get median times for all scenarios
jq '.scenarios[] | {id: .scenario_id, nmap: .nmap_times, rmap: .rmap_times}' results.json
```

## Troubleshooting

### Issue: "nmap: command not found"

```bash
sudo apt-get update
sudo apt-get install -y nmap
nmap --version  # Verify installation
```

### Issue: "R-Map binary not found"

```bash
cd /home/user/R-map
cargo build --release
ls -lh target/release/rmap  # Should exist
```

### Issue: "Docker services not running"

```bash
cd /home/user/R-map/tests/integration
docker-compose down -v
docker-compose up -d
docker-compose ps  # Verify all services are running
```

### Issue: High variance in results

```bash
# Ensure CPU is in performance mode (requires sudo)
sudo cpupower frequency-set -g performance

# Clear system caches before each run
sudo sync
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'

# Disable other processes
# Close browsers, IDEs, etc.
```

### Issue: Benchmarks take too long

```bash
# Reduce iterations
# Edit run_benchmarks.sh:
ITERATIONS=5  # Instead of 10

# Skip slow scenarios
# Comment out TC-007, TC-008, TC-009, TC-010

# Use quick benchmark instead
./quick_benchmark.sh
```

### Issue: Permission denied

```bash
# Make scripts executable
chmod +x /home/user/R-map/benchmarks/scripts/*.sh
chmod +x /home/user/R-map/benchmarks/scripts/*.py

# Check Docker permissions
sudo usermod -aG docker $USER
# Log out and back in
```

## CI/CD Integration

### GitHub Actions Workflow

The benchmark suite integrates with GitHub Actions:

**Triggers:**
- Push to main branch
- Pull requests
- Weekly (Sunday 2am UTC)
- Manual workflow dispatch

**Steps:**
1. Build R-Map in release mode
2. Start Docker test services
3. Run benchmark suite
4. Analyze results
5. Compare with baseline
6. Comment on PR with results
7. Block merge if regression detected
8. Upload artifacts (90-day retention)

**Configuration:**
- Located at `.github/workflows/benchmark.yml`
- Runs on `ubuntu-latest`
- Timeout: 60 minutes

### Viewing CI Results

```bash
# On GitHub:
# 1. Go to Actions tab
# 2. Select "Benchmark" workflow
# 3. Click on specific run
# 4. Download artifacts

# PR comments show:
# - Overall pass/fail status
# - Per-scenario results
# - Performance trends
# - Recommendations
```

## Best Practices

1. **Always run warmup:** First 2 runs discarded to eliminate cold-start effects
2. **Consistent environment:** Same hardware, no background processes
3. **Multiple iterations:** 10 runs minimum for statistical significance
4. **Baseline updates:** Update baseline after verified improvements
5. **Document changes:** Note hardware/config changes in commit messages
6. **Review trends:** Use `generate_trends.py` to track long-term performance
7. **Investigate regressions:** Never ignore performance degradation
8. **Test before commit:** Run benchmarks before pushing performance changes

## Advanced Usage

### Profiling Slow Scenarios

```bash
# Run with perf
perf record -g ./target/release/rmap -p 1-1000 -n localhost
perf report

# Generate flamegraph
perf record -F 99 -g ./target/release/rmap -p 1-1000 -n localhost
perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg
```

### Memory Profiling

```bash
# Using Valgrind (slow but detailed)
valgrind --tool=massif ./target/release/rmap --fast localhost
ms_print massif.out.*

# Using Heaptrack
heaptrack ./target/release/rmap --fast localhost
heaptrack_gui heaptrack.rmap.*
```

### Comparing Multiple Runs

```bash
# Generate trend analysis
python3 scripts/generate_trends.py \
  results/benchmark_20241118_*.json \
  results/benchmark_20241119_*.json \
  results/benchmark_20241120_*.json \
  > results/TRENDS.md
```

## Support

For questions or issues:
1. Check [README.md](/home/user/R-map/benchmarks/README.md)
2. Review [BENCHMARKING_PLAN.md](/home/user/R-map/benchmarks/BENCHMARKING_PLAN.md)
3. See [QUICK_REFERENCE.md](/home/user/R-map/benchmarks/QUICK_REFERENCE.md)
4. Open GitHub issue with benchmark results attached

## References

- **Main README:** `/home/user/R-map/benchmarks/README.md`
- **Test Targets:** `/home/user/R-map/benchmarks/test-targets/README.md`
- **Scripts:** `/home/user/R-map/benchmarks/scripts/`
- **Results:** `/home/user/R-map/benchmarks/results/`
- **Baseline:** `/home/user/R-map/benchmarks/baseline/`
