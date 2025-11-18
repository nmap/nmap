# R-Map vs nmap Performance Benchmarking Plan

**Version:** 1.0  
**Date:** 2025-11-18  
**Status:** Ready for Implementation  
**Owner:** R-Map Team  

## Executive Summary

This document outlines a comprehensive performance benchmarking strategy to validate that R-Map's performance is competitive with or superior to nmap before the v1.0 release. The plan includes test scenarios, metrics, infrastructure requirements, automation strategies, and CI/CD integration.

## Table of Contents

1. [Objectives](#objectives)
2. [Test Scenarios](#test-scenarios)
3. [Metrics & Measurements](#metrics--measurements)
4. [Testing Infrastructure](#testing-infrastructure)
5. [Comparison Methodology](#comparison-methodology)
6. [Automation Strategy](#automation-strategy)
7. [Deliverables](#deliverables)
8. [Timeline](#timeline)
9. [Success Criteria](#success-criteria)

---

## 1. Objectives

### Primary Goals
- **Performance Validation**: Ensure R-Map's scan speed is competitive with nmap (within 20% for common scenarios)
- **Accuracy Verification**: Validate 100% detection accuracy compared to nmap
- **Resource Efficiency**: Prove R-Map uses comparable or less memory/CPU than nmap
- **Regression Prevention**: Establish automated benchmarks to prevent performance degradation

### Secondary Goals
- Identify performance optimization opportunities
- Document performance characteristics for user documentation
- Establish performance baselines for future development
- Create reproducible benchmark environment

---

## 2. Test Scenarios

Based on industry research and nmap's documented performance testing methodology, we'll test across multiple dimensions:

### 2.1 Single Host Scenarios

#### TC-001: Single Host, Top 100 Ports
```bash
# R-Map
rmap scanme.nmap.org --fast

# nmap
nmap scanme.nmap.org --top-ports 100 -T4
```
- **Purpose**: Most common use case
- **Expected Duration**: < 5 seconds
- **Key Metric**: Scan completion time

#### TC-002: Single Host, All Ports (1-65535)
```bash
# R-Map
rmap scanme.nmap.org --all-ports

# nmap
nmap scanme.nmap.org -p- -T4
```
- **Purpose**: Comprehensive port coverage
- **Expected Duration**: 30-60 seconds
- **Key Metric**: Ports scanned per second

#### TC-003: Single Host, Service Detection
```bash
# R-Map
rmap scanme.nmap.org -p 1-1000 -sV

# nmap
nmap scanme.nmap.org -p 1-1000 -sV -T4
```
- **Purpose**: Banner grabbing performance
- **Expected Duration**: 10-20 seconds
- **Key Metric**: Detection accuracy + time

### 2.2 Network Range Scenarios

#### TC-004: /24 Network, Top 100 Ports
```bash
# R-Map
rmap 192.168.1.0/24 --fast --skip-ping

# nmap
nmap 192.168.1.0/24 --top-ports 100 -Pn -T4
```
- **Purpose**: Network sweep performance
- **Expected Duration**: 1-2 minutes
- **Key Metric**: Total scan time, parallelism efficiency

#### TC-005: /24 Network, Custom Port List
```bash
# R-Map
rmap 192.168.1.0/24 -p 22,80,443,3306,8080

# nmap
nmap 192.168.1.0/24 -p 22,80,443,3306,8080 -T4
```
- **Purpose**: Targeted network scanning
- **Expected Duration**: 30-60 seconds
- **Key Metric**: Scan time per host

#### TC-006: /24 Network, Service Detection
```bash
# R-Map
rmap 192.168.1.0/24 -p 1-1000 -sV --skip-ping

# nmap
nmap 192.168.1.0/24 -p 1-1000 -sV -Pn -T4
```
- **Purpose**: Large-scale service enumeration
- **Expected Duration**: 5-10 minutes
- **Key Metric**: Detection rate, memory usage

### 2.3 Large Port Range Scenarios

#### TC-007: Single Host, Large Custom Range
```bash
# R-Map
rmap scanme.nmap.org -p 1-10000

# nmap
nmap scanme.nmap.org -p 1-10000 -T4
```
- **Purpose**: Port range parsing and scanning efficiency
- **Expected Duration**: 10-15 seconds
- **Key Metric**: Scan rate (ports/sec)

#### TC-008: Multiple Targets, Standard Ports
```bash
# R-Map
rmap scanme.nmap.org google.com cloudflare.com -p 80,443

# nmap
nmap scanme.nmap.org google.com cloudflare.com -p 80,443 -T4
```
- **Purpose**: Multi-target efficiency
- **Expected Duration**: < 5 seconds
- **Key Metric**: Target processing overhead

### 2.4 Timing Template Comparisons

We'll run each scenario with different timing profiles to match nmap's templates:

| nmap Template | R-Map Equivalent | Use Case |
|---------------|------------------|----------|
| `-T0` (Paranoid) | `--timeout 300` | IDS evasion |
| `-T1` (Sneaky) | `--timeout 15` | Slow scan |
| `-T2` (Polite) | `--timeout 10` | Low bandwidth |
| `-T3` (Normal) | Default | Standard scan |
| `-T4` (Aggressive) | `--timeout 2 --max-connections 100` | Fast networks |
| `-T5` (Insane) | `--timeout 1 --max-connections 200` | Speed priority |

### 2.5 Stress Test Scenarios

#### TC-009: High Concurrency Test
```bash
# Scan 10 targets simultaneously
for i in {1..10}; do
  rmap 192.168.1.$i -p 1-1000 &
done
wait
```
- **Purpose**: Test resource management under load
- **Key Metric**: System stability, memory growth

#### TC-010: Large CIDR Range
```bash
# R-Map
rmap 10.0.0.0/16 --fast --skip-ping  # Limited to 1000 hosts

# nmap
nmap 10.0.0.0/16 --top-ports 100 -Pn -T4
```
- **Purpose**: Large-scale scanning
- **Key Metric**: Memory efficiency, scan rate consistency

---

## 3. Metrics & Measurements

### 3.1 Primary Metrics

#### Speed Metrics
| Metric | Tool | Formula | Target |
|--------|------|---------|--------|
| **Total Scan Time** | `time` | end_time - start_time | ≤ nmap + 20% |
| **Ports per Second** | Custom | ports_scanned / elapsed_time | ≥ 500 ports/sec |
| **Hosts per Minute** | Custom | hosts_scanned / elapsed_minutes | ≥ 60 hosts/min (network) |
| **Time to First Result** | Custom | first_open_port_time - start_time | < 1 second |

#### Accuracy Metrics
| Metric | Measurement | Target |
|--------|-------------|--------|
| **Detection Rate** | open_ports_found / total_open_ports | 100% |
| **False Positive Rate** | false_positives / total_detections | < 1% |
| **Service ID Accuracy** | correct_services / total_services | ≥ 95% |
| **Version Detection** | versions_detected / services_with_versions | ≥ 90% |

#### Resource Metrics
| Metric | Tool | Target |
|--------|------|--------|
| **Peak Memory (RSS)** | `/usr/bin/time -v`, `ps aux` | ≤ nmap + 20% |
| **CPU Usage (%)** | `top`, `pidstat` | Comparable to nmap |
| **Network Bandwidth** | `iftop`, `nethogs` | Similar to nmap |
| **File Descriptors** | `lsof`, `/proc/PID/fd` | < 1000 |

### 3.2 Secondary Metrics

- **Startup Time**: Time from invocation to first packet sent
- **DNS Resolution Time**: Time spent on reverse DNS lookups
- **Connection Establishment Time**: TCP handshake duration
- **Service Detection Overhead**: Time added by `-sV` flag
- **Output Serialization Time**: JSON/XML generation time

### 3.3 Statistical Requirements

All benchmarks will be run with:
- **Minimum Iterations**: 10 runs per scenario
- **Statistical Measure**: Median (p50) and 95th percentile (p95)
- **Outlier Handling**: Remove top/bottom 5% of results
- **Confidence Interval**: 95% confidence level
- **Coefficient of Variation**: < 15% for repeatability

---

## 4. Testing Infrastructure

### 4.1 Hardware Requirements

#### Development Environment
```yaml
Specification:
  CPU: 4+ cores (Intel/AMD x86_64)
  RAM: 8GB minimum
  Disk: 20GB available
  Network: 1Gbps+ LAN
  OS: Ubuntu 22.04 LTS (or Docker equivalent)
```

#### Production-Like Environment
```yaml
Specification:
  CPU: 8+ cores
  RAM: 16GB
  Disk: SSD (for fast I/O)
  Network: Dedicated 10Gbps network
  OS: Ubuntu 22.04 LTS
```

### 4.2 Network Conditions

#### Controlled Test Network
- **Local Docker Network**: Isolated containers for reproducible tests
- **No External Traffic**: Eliminate network variance
- **Consistent Latency**: 0-1ms RTT (local containers)

#### Real-World Simulation
```bash
# Simulate network conditions with tc (traffic control)
# 10ms latency, 1% packet loss
tc qdisc add dev eth0 root netem delay 10ms loss 1%

# 100ms WAN latency
tc qdisc add dev eth0 root netem delay 100ms
```

### 4.3 Test Target Infrastructure

We'll use the existing R-Map integration test environment with enhancements:

```yaml
# Docker Compose Services (tests/integration/docker-compose.yml)
Services:
  - http-server (nginx:1.24) - Port 8080
  - ssh-server (openssh) - Port 2222
  - ftp-server (vsftpd) - Port 21
  - mysql-server (8.0) - Port 3306
  - redis-server (7) - Port 6379
  - postgres-server (15) - Port 5432
  - dns-server (coredns) - Port 53/UDP
  - smb-server (samba) - Port 445 [NEW]
  - mongodb-server (6.0) - Port 27017 [NEW]
  - elasticsearch (8.0) - Port 9200 [NEW]

Enhancements Needed:
  - Add 50+ closed ports for accuracy testing
  - Add filtered ports (firewall simulation)
  - Add delayed response ports (slow services)
  - Scale to 256 hosts (full /24 network)
```

### 4.4 Software Dependencies

```bash
# Install nmap (benchmark baseline)
apt-get install -y nmap

# Install monitoring tools
apt-get install -y sysstat     # pidstat, iostat
apt-get install -y time        # GNU time with -v flag
apt-get install -y htop        # Interactive process viewer
apt-get install -y iftop       # Network bandwidth monitoring
apt-get install -y jq          # JSON processing

# Install Python dependencies
pip install psutil matplotlib pandas numpy scipy
```

---

## 5. Comparison Methodology

### 5.1 Apples-to-Apples Testing

To ensure fair comparisons, we'll match configurations:

| Feature | R-Map Flag | nmap Flag | Notes |
|---------|------------|-----------|-------|
| **TCP Connect Scan** | `--scan connect` | `-sT` | Default for both |
| **Service Detection** | `-sV` | `-sV` | Must use same timeout |
| **No DNS** | `-n` | `-n` | Disable for speed tests |
| **Timing (Aggressive)** | `--timeout 2 --max-connections 100` | `-T4` | Fast mode |
| **Port Range** | `-p 1-1000` | `-p 1-1000` | Identical ranges |
| **Skip Ping** | `--skip-ping` | `-Pn` | Disable host discovery |

### 5.2 Baseline Establishment

Before comparison testing:

1. **nmap Baseline** - Run all scenarios with nmap 3x to establish baseline
2. **Environment Stability** - Verify <5% variance across nmap runs
3. **Network Health** - Confirm 0% packet loss, <1ms jitter
4. **Service Availability** - Healthcheck all Docker services

### 5.3 Test Execution Protocol

```bash
# For each test scenario:

# 1. Prepare environment
docker-compose -f tests/integration/docker-compose.yml up -d
sleep 30  # Wait for services to stabilize

# 2. Warmup runs (discard)
nmap <target> <flags>  # 2x warmup
rmap <target> <flags>  # 2x warmup

# 3. Synchronized benchmark runs
for i in {1..10}; do
  # Clear DNS cache
  systemd-resolve --flush-caches
  
  # Run nmap with detailed metrics
  /usr/bin/time -v nmap <target> <flags> > nmap_run_$i.txt 2> nmap_time_$i.txt
  
  # Cool down
  sleep 5
  
  # Run rmap with detailed metrics
  /usr/bin/time -v ./target/release/rmap <target> <flags> > rmap_run_$i.txt 2> rmap_time_$i.txt
  
  # Cool down
  sleep 5
done

# 4. Collect system metrics during runs
pidstat -r -u -h 1 > system_metrics.txt &
PIDSTAT_PID=$!

# 5. Kill monitoring
kill $PIDSTAT_PID

# 6. Analyze results
python3 analyze_benchmarks.py nmap_*.txt rmap_*.txt
```

### 5.4 Reproducibility Requirements

- **Identical Target State**: Reset Docker containers between runs
- **No Background Processes**: Kill unnecessary services
- **CPU Governor**: Set to `performance` mode
- **Swap Disabled**: No swapping during tests
- **Kernel Settings**: Consistent network buffer sizes

```bash
# Set CPU to performance mode
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable swap
swapoff -a

# Increase network buffers
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400
```

---

## 6. Automation Strategy

### 6.1 Benchmark Orchestration Script

A master script (`run_benchmarks.sh`) will:

1. **Environment Setup**: Validate dependencies, start Docker services
2. **Baseline Collection**: Run nmap-only tests to establish baseline
3. **Comparison Testing**: Execute all test scenarios
4. **Data Collection**: Gather performance metrics
5. **Analysis**: Generate reports and visualizations
6. **Cleanup**: Stop services, archive results

### 6.2 CI/CD Integration

#### GitHub Actions Workflow (`.github/workflows/benchmark.yml`)

```yaml
name: Performance Benchmarks

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 0'  # Weekly on Sunday at 2am

jobs:
  benchmark:
    runs-on: ubuntu-22.04
    permissions:
      contents: write  # For pushing benchmark results
      pull-requests: write  # For PR comments
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y nmap sysstat time
          cargo install --path .
      
      - name: Start Test Services
        run: |
          docker-compose -f tests/integration/docker-compose.yml up -d
          sleep 30
      
      - name: Run Benchmarks
        run: |
          cd benchmarks/scripts
          chmod +x run_benchmarks.sh
          ./run_benchmarks.sh
      
      - name: Generate Report
        run: |
          python3 benchmarks/scripts/generate_report.py
      
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: benchmarks/results/
      
      - name: Compare with Baseline
        id: compare
        run: |
          python3 benchmarks/scripts/compare_baseline.py
      
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('benchmarks/results/pr_comment.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: report
            });
      
      - name: Fail if Regression
        run: |
          if [ -f benchmarks/results/regression_detected.flag ]; then
            echo "Performance regression detected!"
            exit 1
          fi
```

#### Regression Detection

Benchmarks will fail if:
- **Speed Regression**: >10% slower than baseline
- **Memory Regression**: >15% more memory than baseline
- **Accuracy Regression**: Any decrease in detection rate

### 6.3 Continuous Benchmarking

- **Nightly Runs**: Full benchmark suite runs every night
- **Baseline Updates**: Update baseline on successful releases
- **Historical Tracking**: Store results in `benchmarks/results/history/`
- **Trend Analysis**: Plot performance over time

---

## 7. Deliverables

### 7.1 Scripts & Tools

#### `benchmarks/scripts/run_benchmarks.sh`
Master orchestration script that executes all test scenarios.

#### `benchmarks/scripts/benchmark_runner.py`
Python harness for individual test execution with metrics collection.

#### `benchmarks/scripts/analyze_results.py`
Statistical analysis and comparison report generation.

#### `benchmarks/scripts/generate_report.py`
HTML/Markdown report generator with charts.

#### `benchmarks/scripts/compare_baseline.py`
Regression detection against stored baselines.

### 7.2 Test Harness Components

- **Target Provisioner**: Docker Compose orchestration
- **Metrics Collector**: System resource monitoring
- **Data Aggregator**: Combine results from multiple runs
- **Visualizer**: Generate performance charts

### 7.3 Results & Reports

#### Output Formats

1. **JSON Results** (`benchmarks/results/benchmark_YYYYMMDD_HHMMSS.json`)
   - Raw timing data
   - System metrics
   - Accuracy measurements

2. **Markdown Summary** (`benchmarks/results/SUMMARY.md`)
   - Executive summary
   - Pass/fail by scenario
   - Key findings

3. **HTML Dashboard** (`benchmarks/results/dashboard.html`)
   - Interactive charts
   - Comparison tables
   - Drill-down details

4. **CSV Export** (`benchmarks/results/data.csv`)
   - For external analysis
   - Compatible with Excel/Google Sheets

#### Report Sections

```markdown
# R-Map Performance Benchmark Report
Date: 2025-11-18
R-Map Version: 0.3.0
nmap Version: 7.96

## Executive Summary
- Overall Performance: PASS (within 10% of nmap)
- Accuracy: 100% (matches nmap exactly)
- Resource Usage: PASS (comparable to nmap)

## Detailed Results

### TC-001: Single Host, Top 100 Ports
| Metric | R-Map | nmap | Diff | Status |
|--------|-------|------|------|--------|
| Median Time | 3.2s | 3.0s | +6.7% | ✅ PASS |
| P95 Time | 3.5s | 3.2s | +9.4% | ✅ PASS |
| Ports/sec | 31.3 | 33.3 | -6.0% | ✅ PASS |
| Memory (RSS) | 12.4 MB | 11.2 MB | +10.7% | ✅ PASS |

[Charts and visualizations...]

## Recommendations
1. Optimize DNS resolution path (adds 15% overhead)
2. Consider caching service signatures
3. Reduce memory allocations in port parser
```

### 7.4 CI/CD Integration

- **GitHub Actions Workflow**: `.github/workflows/benchmark.yml`
- **PR Comment Bot**: Automatic benchmark results on PRs
- **Regression Gates**: Block merges on performance degradation
- **Baseline Management**: Automated baseline updates

---

## 8. Timeline

### Week 1: Setup & Infrastructure (3 days)
- [ ] Install nmap on test systems
- [ ] Expand Docker test environment to full /24
- [ ] Create benchmark orchestration scripts
- [ ] Set up metrics collection infrastructure

### Week 2: Baseline & Initial Tests (2 days)
- [ ] Run nmap baseline tests (all scenarios)
- [ ] Validate test environment stability
- [ ] Execute first R-Map comparison runs
- [ ] Identify initial performance gaps

### Week 3: Optimization & Iteration (3 days)
- [ ] Analyze bottlenecks from initial tests
- [ ] Implement performance optimizations
- [ ] Re-run benchmarks to measure improvements
- [ ] Tune configurations for optimal performance

### Week 4: Automation & CI Integration (2 days)
- [ ] Implement CI/CD workflows
- [ ] Create reporting dashboards
- [ ] Document benchmarking process
- [ ] Establish regression testing baseline

**Total Estimated Time**: 10 days (2 weeks with parallelization)

---

## 9. Success Criteria

### Must-Have (P0)
- ✅ **Performance Parity**: R-Map within ±20% of nmap speed for all scenarios
- ✅ **Accuracy Guarantee**: 100% detection rate match with nmap
- ✅ **Resource Efficiency**: Memory/CPU usage comparable to nmap (±20%)
- ✅ **Automated CI**: Benchmark suite integrated into CI/CD pipeline
- ✅ **Regression Protection**: Automatic detection of performance degradation

### Nice-to-Have (P1)
- 🎯 **Superior Performance**: R-Map faster than nmap on parallel scans
- 🎯 **Lower Memory**: R-Map uses <90% of nmap's memory
- 🎯 **Better Accuracy**: R-Map detects services nmap misses
- 🎯 **Comprehensive Docs**: Public benchmark results on website

### Future Enhancements (P2)
- 📊 **Public Dashboard**: Live performance metrics at perf.r-map.io
- 📊 **Community Benchmarks**: User-submitted benchmark results
- 📊 **Competitive Analysis**: Compare against masscan, rustscan
- 📊 **Cloud Benchmarks**: AWS/GCP/Azure environment testing

---

## 10. Risk Mitigation

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| nmap much faster | High | Medium | Focus on accuracy and safety features |
| Test environment instability | Medium | Low | Use Docker for consistency |
| CI runner performance variance | Medium | High | Use self-hosted runners with fixed hardware |
| Benchmark gaming | High | Low | Use real-world scenarios, multiple metrics |

---

## Appendix A: Command Reference

### nmap Timing Templates

```bash
-T0 (Paranoid):   5-minute timeout, serialized probes
-T1 (Sneaky):     15-second timeout, serialized probes
-T2 (Polite):     Slows down to reduce bandwidth
-T3 (Normal):     Default, 1-second timeout
-T4 (Aggressive): Fast, reliable networks (recommended)
-T5 (Insane):     Extremely fast, may sacrifice accuracy
```

### R-Map Equivalent Configurations

```bash
# Normal (default)
rmap <target> -p <ports>

# Aggressive (matches nmap -T4)
rmap <target> -p <ports> --timeout 2 --max-connections 100

# Polite (matches nmap -T2)
rmap <target> -p <ports> --timeout 10 --max-connections 10

# Speed priority (matches nmap -T5)
rmap <target> -p <ports> --timeout 1 --max-connections 200 -n
```

---

## Appendix B: Metrics Collection Commands

```bash
# CPU and memory profiling
/usr/bin/time -v <command>

# Real-time resource monitoring
pidstat -r -u -h 1 -p <PID>

# Network bandwidth
iftop -i eth0 -t -s 10

# Connection tracking
ss -tan | grep ESTAB | wc -l

# File descriptor count
lsof -p <PID> | wc -l
```

---

## References

1. [Nmap Performance Optimization](https://nmap.org/book/performance.html)
2. [Nmap Timing Templates](https://nmap.org/book/performance-timing-templates.html)
3. [Port Scanner Benchmark Study 2024](https://arxiv.org/pdf/2303.11282)
4. [Network Vulnerability Scanner Benchmark](https://pentest-tools.com/blog/network-vulnerability-scanner-benchmark-2024)

---

**Document Version History:**
- v1.0 (2025-11-18): Initial comprehensive benchmarking plan

**Prepared by:** R-Map Performance Team  
**Approved by:** [Pending]
