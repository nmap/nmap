# R-Map Performance Benchmarking

This directory contains the comprehensive performance benchmarking suite for comparing R-Map against nmap.

## Quick Start

### Prerequisites

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y nmap sysstat time jq python3 python3-pip docker.io docker-compose

# Build R-Map
cargo build --release

# Verify installation
nmap --version
./target/release/rmap --version
```

### Run Benchmarks

```bash
# Full benchmark suite (10 iterations per scenario)
cd benchmarks/scripts
./run_benchmarks.sh

# Results will be saved to benchmarks/results/
# Summary report will be generated automatically
```

### Quick Test (Single Run)

```bash
# Compare single scenario
cd benchmarks/scripts
./quick_benchmark.sh
```

## Directory Structure

```
benchmarks/
├── README.md                    # This file
├── BENCHMARKING_PLAN.md        # Comprehensive planning document
├── scripts/
│   ├── run_benchmarks.sh       # Master orchestration script
│   ├── analyze_results.py      # Statistical analysis
│   ├── compare_baseline.py     # Regression detection
│   ├── generate_pr_comment.py  # PR comment generator
│   └── quick_benchmark.sh      # Quick manual test
├── results/                     # Benchmark results (gitignored)
│   ├── benchmark_YYYYMMDD.json
│   ├── SUMMARY_*.md
│   └── analysis_*.json
└── baseline/                    # Performance baselines
    └── baseline.json
```

## Test Scenarios

### TC-001: Single Host, Top 100 Ports
Most common use case - fast scan of top ports.

```bash
# R-Map
rmap localhost --fast -n

# nmap
nmap localhost --top-ports 100 -n -T4
```

### TC-002: Single Host, Custom Ports
Targeted port scanning.

```bash
# R-Map
rmap localhost -p 22,80,443,3306,6379,5432 -n

# nmap
nmap localhost -p 22,80,443,3306,6379,5432 -n -T4
```

### TC-003: Service Detection
Banner grabbing and version detection.

```bash
# R-Map
rmap localhost -p 8080,2222,21,3306 -sV -n

# nmap
nmap localhost -p 8080,2222,21,3306 -sV -n -T4
```

### TC-004: Large Port Range
Scanning 1-1000 ports.

```bash
# R-Map
rmap localhost -p 1-1000 -n

# nmap
nmap localhost -p 1-1000 -n -T4
```

### TC-005: Extended Port Range
Comprehensive port coverage (1-10000).

```bash
# R-Map
rmap localhost -p 1-10000 -n

# nmap
nmap localhost -p 1-10000 -n -T4
```

## Metrics Collected

### Speed Metrics
- **Total Scan Time**: Wall-clock time from start to finish
- **Ports per Second**: Scanning throughput
- **Time to First Result**: Latency to first open port detection

### Resource Metrics
- **Peak Memory (RSS)**: Maximum memory usage during scan
- **CPU Usage (%)**: Average CPU utilization
- **File Descriptors**: Open socket count

### Accuracy Metrics
- **Detection Rate**: Percentage of open ports found
- **False Positive Rate**: Incorrect open port reports
- **Service ID Accuracy**: Correct service identification

## Interpreting Results

### Success Criteria

A benchmark **PASSES** if:
- ✅ Speed within ±20% of nmap
- ✅ Memory within ±20% of nmap
- ✅ 100% detection accuracy (no missed ports)

### Example Output

```
✅ TC-001: Single Host, Top 100 Ports
   Time:   nmap=3.0s, rmap=3.2s (+6.7%) ✅
   Memory: nmap=11.2MB, rmap=12.4MB (+10.7%) ✅

❌ TC-002: Single Host, Custom Ports
   Time:   nmap=2.5s, rmap=3.5s (+40.0%) ❌
   Memory: nmap=10.0MB, rmap=11.0MB (+10.0%) ✅
```

## CI/CD Integration

Benchmarks run automatically on:
- Every push to `main`
- Every pull request
- Weekly (Sunday 2am UTC)

### Workflow: `.github/workflows/benchmark.yml`

The CI workflow:
1. Builds R-Map in release mode
2. Starts Docker test services
3. Runs full benchmark suite
4. Analyzes results
5. Compares with baseline
6. Posts results to PR (if applicable)
7. **Fails the build** if regression detected

### Regression Detection

A **performance regression** is detected if:
- Speed degrades >10% vs baseline
- Memory usage increases >15% vs baseline

When regression is detected:
- ❌ PR checks fail (blocks merge)
- 🐛 GitHub issue is created automatically
- 💬 PR comment shows detailed comparison

## Manual Testing

### Test Against Real Targets

```bash
# Official nmap test target (always available)
rmap scanme.nmap.org -p 22,80,443 -sV
nmap scanme.nmap.org -p 22,80,443 -sV -T4

# Compare timing manually
time rmap scanme.nmap.org --fast
time nmap scanme.nmap.org --top-ports 100 -T4
```

### Local Docker Test Environment

```bash
# Start test services
cd tests/integration
docker-compose up -d

# Wait for services
sleep 30

# Run benchmark
cd ../../benchmarks/scripts
./run_benchmarks.sh

# Cleanup
cd ../../tests/integration
docker-compose down
```

## Baseline Management

### Creating a New Baseline

After confirming good performance:

```bash
# Copy latest results as baseline
cp benchmarks/results/benchmark_YYYYMMDD.json benchmarks/baseline/baseline.json

# Commit baseline
git add benchmarks/baseline/baseline.json
git commit -m "chore: Update performance baseline"
git push
```

### Updating Baseline (Automatic)

On successful merge to `main`, the CI automatically updates the baseline if no regressions are detected.

## Troubleshooting

### "nmap not found"

```bash
sudo apt-get install -y nmap
```

### "Permission denied" errors

Some operations require root (e.g., clearing caches):

```bash
sudo ./run_benchmarks.sh
```

### Docker services not starting

```bash
# Check Docker status
docker ps

# View logs
cd tests/integration
docker-compose logs

# Restart services
docker-compose down -v
docker-compose up -d
```

### Inconsistent results (high variance)

Ensure system is idle:

```bash
# Kill unnecessary processes
# Disable background services
# Run on dedicated hardware

# Set CPU to performance mode
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## Advanced Usage

### Custom Iterations

```bash
# Edit run_benchmarks.sh
ITERATIONS=20  # Default is 10
```

### Selective Scenarios

```bash
# Edit run_benchmarks.sh to comment out unwanted scenarios
# Or create a custom script:

run_scenario "TC-001" "Custom Test" \
            "-p 80,443 -n" \
            "-p 80,443 -n -T4"
```

### Export Results for Analysis

```bash
# Results are in JSON format
cat benchmarks/results/benchmark_*.json | jq .

# Import into Python/R for custom analysis
python3 -c "
import json
with open('benchmarks/results/benchmark_20241118.json') as f:
    data = json.load(f)
    print(data['scenarios'][0])
"
```

## Performance Optimization Tips

Based on benchmark results, consider:

1. **DNS Resolution**: Use `-n` to skip reverse DNS (15-20% faster)
2. **Parallelism**: Increase `--max-connections` for network scans
3. **Timeouts**: Reduce `--timeout` for fast networks
4. **Port Selection**: Scan only necessary ports

## Contributing

To add new benchmark scenarios:

1. Edit `run_benchmarks.sh`
2. Add scenario with `run_scenario` function
3. Document in `BENCHMARKING_PLAN.md`
4. Run locally to verify
5. Submit PR with updated baselines

## References

- [Nmap Performance Guide](https://nmap.org/book/performance.html)
- [Benchmarking Plan](./BENCHMARKING_PLAN.md)
- [R-Map Documentation](../README.md)

---

**Last Updated:** 2025-11-18  
**Maintained by:** R-Map Performance Team
