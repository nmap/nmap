# R-Map Load Testing - Quick Start Guide

## 5-Minute Setup

### Step 1: Install Prerequisites

```bash
# Install Docker (if not already installed)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Logout and login for changes to take effect

# Install jq (JSON processor)
sudo apt install jq -y  # Ubuntu/Debian
sudo yum install jq -y  # CentOS/RHEL
```

### Step 2: Build R-Map

```bash
cd /home/user/R-map
cargo build --release
```

### Step 3: Run First Test

```bash
cd /home/user/R-map/scripts

# Run small test with 100 hosts
./load_test.sh test
```

That's it! The test will:
1. Spawn 100 Docker containers simulating network hosts
2. Run R-Map scan with performance monitoring
3. Generate detailed metrics and reports
4. Clean up all test infrastructure

## Expected Output

### Console Output

```
==========================================
  R-Map Load Testing Framework
==========================================

[INFO] Scenario: Test Scenario - Development & Validation
[INFO] Hosts: 100
[INFO] Ports: 22,80,443,3306,5432
[INFO] Timeout: 2000ms
[INFO] Concurrency: 100

==> Checking prerequisites

[SUCCESS] Docker found
[SUCCESS] R-Map binary found
[SUCCESS] spawn_targets.sh found

==> Spawning 100 target hosts

[INFO] Using Docker Container Grid method for 100 hosts
[INFO] Creating Docker network: rmap-loadtest (subnet: 172.20.0.0/16)
[SUCCESS] Network created successfully
[INFO] Building lightweight responder image...
[SUCCESS] Responder image built
[INFO] Spawning 100 target containers...
[SUCCESS] All 100 containers spawned successfully
[SUCCESS] Spawned 100 targets in 45s

==> Starting monitoring

[INFO] Monitoring: Metrics will be collected during scan

==> Running R-Map scan

[INFO] Command: /home/user/R-map/target/release/rmap --targets /home/user/R-map/load-test-results/20231118_143022/targets.txt --ports 22,80,443,3306,5432 --timeout 2000 --max-connections 100 --output /home/user/R-map/load-test-results/20231118_143022/results.json
[INFO] Starting scan...
[SUCCESS] Scan completed in 42s

==> Calculating statistics

[SUCCESS] Statistics calculated

==> Generating summary report

[SUCCESS] Summary report generated: /home/user/R-map/load-test-results/20231118_143022/SUMMARY.md
[INFO] Latest results symlinked to: /home/user/R-map/load-test-results/latest

==> Cleaning up test infrastructure

[INFO] Searching for R-Map target containers...
[INFO] Found 100 target container(s), removing...
[SUCCESS] Removed 100 container(s)
[INFO] Removing network: rmap-loadtest
[SUCCESS] Network removed
[SUCCESS] Cleanup complete

==========================================
  LOAD TEST COMPLETE
==========================================

## Performance Metrics

| Metric | Value |
|--------|-------|
| Total Port Checks | 500 |
| Checks/Second | 11 |
| Duration | 42s |
| Completion Rate | 100.00% |

## Resource Usage

| Resource | Peak | Average |
|----------|------|---------|
| Memory (MB) | 248 | 187 |

## Results

- **Open Ports**: 500
- **Closed Ports**: 0
- **Filtered Ports**: 0

✅ **GOOD** - Met target performance (>500 checks/sec)
✅ **MEMORY: EXCELLENT** - Under 1GB (stretch goal)

Full report: /home/user/R-map/load-test-results/20231118_143022/SUMMARY.md

[SUCCESS] All results saved to: /home/user/R-map/load-test-results/20231118_143022
```

### Generated Files

```
load-test-results/20231118_143022/
├── SUMMARY.md           # Human-readable summary report
├── metadata.json        # Test configuration
├── targets.txt          # List of 100 target IPs
├── results.json         # R-Map scan results
├── metrics.json         # Time-series performance metrics
├── statistics.json      # Calculated statistics
├── test.log            # Detailed execution log
└── duration.txt        # Scan duration in seconds
```

## Next Steps

### Run Larger Tests

```bash
# 10K hosts - Wide network scan
./load_test.sh scenario1

# 1K hosts - Deep port scan (all 65K ports)
./load_test.sh scenario2

# 50K hosts - Fast reconnaissance
./load_test.sh scenario3
```

### View Results

```bash
# View latest summary
cat /home/user/R-map/load-test-results/latest/SUMMARY.md

# View metrics over time
jq '.[] | {timestamp, memory_mb, cpu_percent}' \
  /home/user/R-map/load-test-results/latest/metrics.json

# View statistics
jq . /home/user/R-map/load-test-results/latest/statistics.json
```

### Custom Scenarios

Edit `/home/user/R-map/scripts/scenarios.conf`:

```bash
# Add custom scenario
SCENARIO_CUSTOM_HOSTS=5000
SCENARIO_CUSTOM_PORTS="80,443,8080,8443"
SCENARIO_CUSTOM_DESC="Custom Web Server Scan"
SCENARIO_CUSTOM_TIMEOUT=1000
SCENARIO_CUSTOM_CONCURRENCY=2000
```

Run:
```bash
./load_test.sh custom
```

## Troubleshooting

### Docker Permission Denied

```bash
sudo usermod -aG docker $USER
# Logout and login
```

### Clean Up Stuck Containers

```bash
./cleanup_targets.sh --with-images
```

### View Detailed Logs

```bash
cat /home/user/R-map/load-test-results/latest/test.log
```

## Performance Tips

1. **Start Small**: Always test with `scenario_test` (100 hosts) first
2. **Scale Gradually**: 100 → 1K → 10K → 50K hosts
3. **Monitor Resources**: Watch `htop` during large tests
4. **Tune Concurrency**: Increase in `scenarios.conf` for better throughput
5. **Use SSD**: Docker performs better on SSD storage

## Complete Documentation

See `/home/user/R-map/scripts/README.md` for:
- Detailed architecture
- All scenarios explained
- Troubleshooting guide
- Advanced usage examples
- Performance optimization
