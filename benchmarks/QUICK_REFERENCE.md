# Benchmarking Quick Reference

## Quick Commands

### Run Full Benchmark Suite
```bash
cd benchmarks/scripts
./run_benchmarks.sh
```

### Quick Manual Test
```bash
cd benchmarks/scripts
./quick_benchmark.sh
```

### Analyze Existing Results
```bash
python3 benchmarks/scripts/analyze_results.py benchmarks/results/benchmark_20241118.json
```

### Compare with Baseline
```bash
python3 benchmarks/scripts/compare_baseline.py \
  benchmarks/results/benchmark_latest.json \
  benchmarks/baseline/baseline.json
```

### Generate Trend Report
```bash
python3 benchmarks/scripts/generate_trends.py benchmarks/results/benchmark_*.json
```

## Test Scenarios

### TC-001: Fast Scan (Top 100 Ports)
```bash
# R-Map
rmap localhost --fast -n

# nmap
nmap localhost --top-ports 100 -n -T4
```

### TC-002: Custom Ports
```bash
# R-Map
rmap localhost -p 22,80,443,3306,6379,5432 -n

# nmap
nmap localhost -p 22,80,443,3306,6379,5432 -n -T4
```

### TC-003: Service Detection
```bash
# R-Map
rmap localhost -p 8080,2222,21,3306 -sV -n

# nmap
nmap localhost -p 8080,2222,21,3306 -sV -n -T4
```

### TC-004: Port Range (1-1000)
```bash
# R-Map
rmap localhost -p 1-1000 -n

# nmap
nmap localhost -p 1-1000 -n -T4
```

### TC-005: Extended Range (1-10000)
```bash
# R-Map
rmap localhost -p 1-10000 -n

# nmap
nmap localhost -p 1-10000 -n -T4
```

## Docker Commands

### Start Test Services
```bash
cd tests/integration
docker-compose up -d
sleep 30  # Wait for services to be ready
```

### Check Service Status
```bash
docker-compose ps
docker-compose logs
```

### Stop Services
```bash
docker-compose down -v
```

## Troubleshooting

### Install nmap
```bash
sudo apt-get install -y nmap
```

### Build R-Map
```bash
cargo build --release
```

### Check Versions
```bash
nmap --version
./target/release/rmap --version
```

### Clear DNS Cache
```bash
systemd-resolve --flush-caches
```

### Set CPU to Performance Mode
```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## CI/CD Commands

### Trigger Benchmark Workflow Manually
```bash
gh workflow run benchmark.yml
```

### View Workflow Status
```bash
gh run list --workflow=benchmark.yml
```

### Download Benchmark Results
```bash
gh run download <run-id> -n benchmark-results
```

## Results Locations

- **JSON Results:** `benchmarks/results/benchmark_YYYYMMDD_HHMMSS.json`
- **Summary Report:** `benchmarks/results/SUMMARY_benchmark_YYYYMMDD_HHMMSS.md`
- **Analysis:** `benchmarks/results/analysis_benchmark_YYYYMMDD_HHMMSS.json`
- **Baseline:** `benchmarks/baseline/baseline.json`

## Success Criteria

| Metric | Threshold | Status |
|--------|-----------|--------|
| Speed | Within ±20% of nmap | ✅/❌ |
| Memory | Within ±20% of nmap | ✅/❌ |
| Accuracy | 100% match | ✅/❌ |

## Regression Thresholds

- **Speed Regression:** >10% slower than baseline
- **Memory Regression:** >15% more memory than baseline

## Common Issues

### Docker services not starting
```bash
docker-compose down -v
docker-compose up -d
docker-compose ps
```

### Permission denied
```bash
sudo ./run_benchmarks.sh
```

### nmap not found
```bash
sudo apt-get install -y nmap
```

### High result variance
- Ensure system is idle
- Set CPU governor to performance
- Clear caches before each run
- Use consistent hardware

## Documentation Links

- **Full Plan:** [BENCHMARKING_PLAN.md](BENCHMARKING_PLAN.md)
- **README:** [README.md](README.md)
- **Executive Summary:** [../docs/BENCHMARKING_EXECUTIVE_SUMMARY.md](../docs/BENCHMARKING_EXECUTIVE_SUMMARY.md)
- **Main README:** [../README.md](../README.md)
