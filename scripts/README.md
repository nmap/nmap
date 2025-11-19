# R-Map Load Testing Scripts

Complete load testing infrastructure for validating R-Map's performance at scale (10K+ hosts).

## Overview

This directory contains scripts to:
- Spawn simulated target networks (100 to 50K+ hosts)
- Run performance benchmarks
- Collect detailed metrics
- Generate summary reports
- Clean up test infrastructure

## Files

| File | Description |
|------|-------------|
| `load_test.sh` | Master orchestrator - run this to execute load tests |
| `spawn_targets.sh` | Creates simulated target network using Docker |
| `cleanup_targets.sh` | Removes all test infrastructure |
| `scenarios.conf` | Pre-configured test scenarios |
| `README.md` | This file |

## Prerequisites

### Required

- **Docker**: Container runtime for simulating targets
  ```bash
  # Install Docker (Ubuntu/Debian)
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker $USER
  # Logout and login for group changes to take effect
  ```

- **jq**: JSON processor for metrics analysis
  ```bash
  sudo apt install jq  # Ubuntu/Debian
  ```

- **R-Map**: Built in release mode
  ```bash
  cd /home/user/R-map
  cargo build --release
  ```

### Optional

- **Prometheus/Grafana**: For real-time monitoring dashboards
- **docker-compose**: For easier monitoring stack management

## Quick Start

### 1. Make Scripts Executable

```bash
chmod +x /home/user/R-map/scripts/*.sh
```

### 2. Run Test Scenario

```bash
cd /home/user/R-map/scripts

# Small test (100 hosts) - recommended for first run
./load_test.sh test

# Wide network scan (10K hosts)
./load_test.sh scenario1

# Deep port scan (1K hosts, all ports)
./load_test.sh scenario2

# Fast reconnaissance (50K hosts)
./load_test.sh scenario3

# Stress test (100K hosts - requires cloud)
./load_test.sh scenario4
```

### 3. View Results

```bash
# View summary report
cat /home/user/R-map/load-test-results/latest/SUMMARY.md

# View detailed metrics
jq . /home/user/R-map/load-test-results/latest/metrics.json

# View statistics
jq . /home/user/R-map/load-test-results/latest/statistics.json
```

### 4. Cleanup

```bash
# Cleanup is automatic, but can be run manually
./cleanup_targets.sh

# Remove Docker images too
./cleanup_targets.sh --with-images
```

## Test Scenarios

### Scenario Test (Development)
- **Hosts**: 100
- **Ports**: 22, 80, 443, 3306, 5432
- **Total Checks**: 500
- **Duration**: ~10-30 seconds
- **Use Case**: Quick validation, development testing

### Scenario 1: Wide Network Scan
- **Hosts**: 10,000
- **Ports**: 80, 443, 22, 21, 25, 3389, 3306, 5432, 8080, 9090
- **Total Checks**: 100,000
- **Duration**: 10-30 minutes
- **Use Case**: Enterprise network discovery

### Scenario 2: Deep Single Subnet
- **Hosts**: 1,000
- **Ports**: 1-65535 (all ports)
- **Total Checks**: 65,535,000
- **Duration**: 3-6 hours
- **Use Case**: Comprehensive security audit

### Scenario 3: Fast Reconnaissance
- **Hosts**: 50,000
- **Ports**: 22, 80, 443, 3389, 3306, 5432, 8080, 8443, 9090, 27017
- **Total Checks**: 500,000
- **Duration**: 5-15 minutes
- **Use Case**: Cloud environment sweep

### Scenario 4: Stress Test
- **Hosts**: 100,000
- **Ports**: 80, 443, 22
- **Total Checks**: 300,000
- **Duration**: 10-20 minutes
- **Use Case**: Breaking point analysis
- **Note**: Requires cloud infrastructure (not supported locally)

## How It Works

### 1. Target Spawning (`spawn_targets.sh`)

Creates simulated networks using different strategies based on scale:

#### Small Scale (<5K hosts)
- **Method**: Docker Container Grid
- **How**: Each target is a separate Docker container
- **Pros**: Realistic service responses, protocol diversity
- **Cons**: Resource intensive
- **Command**:
  ```bash
  ./spawn_targets.sh 100
  ```

#### Medium Scale (5K-50K hosts)
- **Method**: iptables NAT with IP aliases
- **How**: Single container with multiple IP addresses
- **Pros**: Efficient scaling, low resource usage
- **Cons**: Less realistic responses
- **Command**:
  ```bash
  ./spawn_targets.sh 10000
  ```

#### Large Scale (>50K hosts)
- **Method**: Cloud infrastructure required
- **How**: AWS/GCP/Azure instances
- **Note**: Script will error with instructions
- **Estimated Cost**: ~$200-800/hour depending on provider

### 2. Load Test Orchestration (`load_test.sh`)

Master script workflow:

1. **Parse Scenario**: Loads configuration from `scenarios.conf`
2. **Setup Environment**: Creates results directory with timestamp
3. **Check Prerequisites**: Verifies Docker, R-Map binary, scripts
4. **Spawn Targets**: Calls `spawn_targets.sh` to create network
5. **Start Monitoring**: Initializes metrics collection
6. **Run Scan**: Executes R-Map with performance monitoring
7. **Calculate Stats**: Analyzes results and metrics
8. **Generate Report**: Creates markdown summary
9. **Cleanup**: Removes test infrastructure

### 3. Metrics Collection

Automatically collected during scan:

- **Memory Usage**: RSS, heap size, growth trend
- **CPU Usage**: Percentage, user/system time
- **Network I/O**: Bytes sent/received
- **Throughput**: Ports scanned per second
- **Results**: Open/closed/filtered port counts
- **Completion Rate**: Percentage of successful checks

### 4. Results Structure

```
load-test-results/
├── 20231118_143022/          # Timestamp-based directory
│   ├── SUMMARY.md            # Human-readable summary
│   ├── metadata.json         # Test configuration
│   ├── targets.txt           # List of target IPs
│   ├── results.json          # R-Map scan results
│   ├── metrics.json          # Time-series metrics
│   ├── statistics.json       # Calculated statistics
│   ├── test.log              # Detailed execution log
│   └── duration.txt          # Scan duration
└── latest -> 20231118_143022/  # Symlink to most recent
```

## Interpreting Results

### Summary Report

The `SUMMARY.md` file contains:

1. **Configuration**: Scenario parameters
2. **Performance Metrics**: Throughput, duration, completion rate
3. **Resource Usage**: Memory and CPU statistics
4. **Results**: Port state counts
5. **Assessment**: Performance vs. targets

### Performance Targets

| Metric | Target | Stretch Goal | Status |
|--------|--------|--------------|--------|
| Throughput | 500+ ports/sec | 2,000+ ports/sec | ✅ Good / ⚠️ Needs Improvement |
| Memory (10K) | <2GB | <1GB | ✅ Good / ⚠️ High |
| CPU Average | 60-80% | 50-70% | Measured in metrics.json |
| Completion | >99% | >99.9% | Shown in summary |
| Error Rate | <1% | <0.1% | Calculate from logs |

### Example Summary

```markdown
# R-Map Load Test Summary

**Scenario**: Wide Network Scan - Enterprise Discovery
**Duration**: 185s

## Performance Metrics

| Metric | Value |
|--------|-------|
| Total Port Checks | 100,000 |
| Checks/Second | 540 |
| Completion Rate | 99.8% |

## Resource Usage

| Resource | Peak | Average |
|----------|------|---------|
| Memory (MB) | 1,247 | 983 |

✅ **GOOD** - Met target performance (>500 checks/sec)
✅ **MEMORY: EXCELLENT** - Under 1GB (stretch goal)
```

## Troubleshooting

### Docker Permission Denied

**Problem**: `permission denied while trying to connect to Docker daemon`

**Solution**:
```bash
sudo usermod -aG docker $USER
# Logout and login
```

### Out of Memory

**Problem**: Test fails with OOM error

**Solution**:
- Reduce number of hosts
- Reduce concurrency
- Use iptables NAT method (automatically chosen for >5K hosts)
- Add swap space

### Port Already in Use

**Problem**: Docker containers fail to start

**Solution**:
```bash
# Clean up previous test
./cleanup_targets.sh --with-images

# Check for conflicting containers
docker ps -a
```

### Slow Performance

**Problem**: Scan slower than expected

**Solutions**:
- Check network connectivity to Docker containers
- Increase concurrency in `scenarios.conf`
- Reduce timeout value
- Check system resources (CPU, memory)
- Use SSD for Docker storage

### R-Map Not Found

**Problem**: `R-Map binary not found`

**Solution**:
```bash
cd /home/user/R-map
cargo build --release
```

### No Results Generated

**Problem**: `results.json` is empty or missing

**Solutions**:
- Check `test.log` for errors
- Verify targets are reachable: `docker exec rmap-target-1 echo "ok"`
- Ensure Docker network is working
- Check R-Map command line in logs

## Advanced Usage

### Custom Scenarios

Edit `scenarios.conf`:

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

### Skip Cleanup

Keep infrastructure running for debugging:

```bash
CLEANUP=no ./load_test.sh test
```

Then inspect manually:
```bash
docker ps
docker exec -it rmap-target-1 sh
```

Cleanup later:
```bash
./cleanup_targets.sh
```

### Manual Target Spawning

```bash
# Spawn targets only
./spawn_targets.sh 1000 > targets.txt

# Use with R-Map directly
/home/user/R-map/target/release/rmap \
  --targets targets.txt \
  --ports 80,443 \
  --timeout 2000 \
  --max-connections 1000

# Cleanup
./cleanup_targets.sh
```

### Monitoring with Prometheus/Grafana

(TODO: Add Prometheus exporter integration)

```bash
# Start monitoring stack
docker-compose -f monitoring/docker-compose.yml up -d

# Run load test
./load_test.sh scenario1

# View dashboard
firefox http://localhost:3000
```

## Performance Optimization Tips

1. **Increase Concurrency**: Edit `scenarios.conf` and increase `CONCURRENCY` values
2. **Reduce Timeout**: Lower timeout for faster scans (trade-off: more timeouts)
3. **Use Release Build**: Always use `--release` for accurate performance
4. **System Tuning**:
   ```bash
   # Increase file descriptors
   ulimit -n 65536

   # Increase network buffers
   sudo sysctl -w net.core.rmem_max=16777216
   sudo sysctl -w net.core.wmem_max=16777216
   ```

## Contributing

To add new scenarios or improve scripts:

1. Edit `scenarios.conf` for new test scenarios
2. Modify `spawn_targets.sh` for new target types
3. Update `load_test.sh` for new metrics
4. Document changes in this README

## License

Same as R-Map project.

## Support

For issues or questions:
1. Check `test.log` in results directory
2. Review this README's troubleshooting section
3. Open an issue in the R-Map repository
