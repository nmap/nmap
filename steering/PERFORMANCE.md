# R-Map Performance Tuning Guide

**Version:** 1.0.0
**Last Updated:** 2025-01-19

## Table of Contents

- [Overview](#overview)
- [Performance Characteristics](#performance-characteristics)
- [Tuning Parameters](#tuning-parameters)
- [Timing Templates](#timing-templates)
- [Resource Requirements](#resource-requirements)
- [Scaling Recommendations](#scaling-recommendations)
- [Optimization Strategies](#optimization-strategies)
- [Benchmarking](#benchmarking)
- [Troubleshooting Performance](#troubleshooting-performance)

---

## Overview

R-Map is designed for high performance while maintaining security and accuracy. This guide helps you tune R-Map for your specific use cases, from single-host scans to massive network surveys.

### Performance Goals

- **Throughput:** 500-800 ports/second
- **Memory:** <100MB typical, <2GB for 10K+ hosts
- **Latency:** Sub-second for fast scans
- **Scalability:** Linear scaling to 50K+ hosts

### Key Performance Factors

1. **Network latency** - RTT to target hosts
2. **Scan type** - SYN vs Connect vs UDP
3. **Port count** - Fewer ports = faster scans
4. **Service detection** - Banner grabbing adds overhead
5. **Concurrency** - Parallel connections vs resource usage

---

## Performance Characteristics

### Scan Speed Comparison (vs nmap)

Based on comprehensive benchmarking (see `/benchmarks/`):

| Scenario | R-Map | nmap | Difference | Analysis |
|----------|-------|------|------------|----------|
| **Single Host (100 ports)** | 1.2s | 1.1s | +9% | Acceptable overhead |
| **Single Host (1000 ports)** | 8.5s | 8.0s | +6% | Competitive |
| **Network /24 (256 hosts)** | 45s | 48s | -6% | **Faster** (Tokio async) |
| **Network + Service Detect** | 180s | 185s | -3% | **Faster** |

**Conclusion:** R-Map is **competitive** for single hosts and **faster** for network scans.

### Throughput Metrics

| Metric | Performance | Conditions |
|--------|-------------|------------|
| **Port scan rate** | 500-800 ports/sec | 1ms latency, 100 connections |
| **Host discovery** | 100-200 hosts/sec | ICMP + TCP ping |
| **Service detection** | 50-100 services/sec | Banner grabbing |
| **OS fingerprinting** | 10-20 hosts/sec | Active + passive |

### Resource Usage

| Workload | Memory (RSS) | CPU | File Descriptors |
|----------|--------------|-----|------------------|
| **Idle** | 15MB | <1% | 20 |
| **Single host** | 25MB | 10-30% | 50-100 |
| **100 hosts** | 80MB | 40-60% | 200-300 |
| **1K hosts** | 185MB | 70-90% | 512 |
| **10K hosts** | 1.8GB | 90-100% | 1024 |

---

## Tuning Parameters

### Connection Limits

Control parallelism with `--max-connections`:

```bash
# Conservative (low CPU/memory)
rmap 192.168.1.0/24 --max-connections 50

# Default (balanced)
rmap 192.168.1.0/24 --max-connections 100

# Aggressive (high throughput)
rmap 192.168.1.0/24 --max-connections 500

# Maximum (careful!)
rmap 192.168.1.0/24 --max-connections 1000
```

**Guidelines:**

| Use Case | Recommended | Reasoning |
|----------|-------------|-----------|
| **Single host** | 50-100 | Avoid overwhelming target |
| **Small network (<10 hosts)** | 100-200 | Balance speed and resources |
| **Medium network (10-100)** | 200-500 | Maximize throughput |
| **Large network (100+)** | 500-1000 | Full parallelism |
| **Stealth scanning** | 10-50 | Avoid detection |

**Warning:** High connection counts can:
- Trigger IDS/IPS alerts
- Overwhelm underpowered targets
- Exhaust file descriptors (`ulimit -n`)
- Cause network congestion

### Timeout Configuration

Adjust timeouts with `--timeout`:

```bash
# Fast scan (may miss slow services)
rmap example.com --timeout 1

# Default (balanced)
rmap example.com --timeout 3

# Patient (catch slow responses)
rmap example.com --timeout 10

# Very patient (for high-latency networks)
rmap example.com --timeout 30
```

**Timeout Selection Guide:**

| Network Type | Recommended Timeout | Reason |
|--------------|---------------------|--------|
| **Local network (LAN)** | 1-2s | Low latency |
| **Internet hosts** | 3-5s | Moderate latency |
| **Satellite/high-latency** | 10-30s | High RTT |
| **Service detection** | 5-10s | Banner reading time |

**Formula:** `timeout = 3 × average_rtt + service_overhead`

### Global Scan Timeout

Prevent indefinite scans with `--max-scan-duration`:

```bash
# Quick scan (5 minutes max)
rmap 192.168.1.0/24 --max-scan-duration 300

# Default (30 minutes)
rmap 192.168.1.0/24 --max-scan-duration 1800

# Long scan (2 hours)
rmap 10.0.0.0/16 --max-scan-duration 7200
```

**Recommended values:**
- **Fast scan (<100 ports):** 300-900s (5-15 min)
- **Full scan (1-1000 ports):** 1800-3600s (30-60 min)
- **Large network scan:** 7200-14400s (2-4 hours)

---

## Timing Templates

Pre-configured timing profiles for common scenarios:

### T0 - Paranoid (Stealth)
```bash
rmap example.com --timing paranoid
```

- **Max connections:** 1
- **Timeout:** 30s
- **Delays:** 300s between probes
- **Use case:** Evading IDS, stealth reconnaissance

### T1 - Sneaky
```bash
rmap example.com --timing sneaky
```

- **Max connections:** 10
- **Timeout:** 15s
- **Delays:** 15s between probes
- **Use case:** Slow, stealthy scanning

### T2 - Polite
```bash
rmap example.com --timing polite
```

- **Max connections:** 25
- **Timeout:** 10s
- **Delays:** 1s between probes
- **Use case:** Low-impact scanning

### T3 - Normal (Default)
```bash
rmap example.com --timing normal
```

- **Max connections:** 100
- **Timeout:** 3s
- **Delays:** Minimal
- **Use case:** Balanced performance

### T4 - Aggressive
```bash
rmap example.com --timing aggressive
```

- **Max connections:** 500
- **Timeout:** 2s
- **Delays:** None
- **Use case:** Fast scanning, trusted networks

### T5 - Insane
```bash
rmap example.com --timing insane
```

- **Max connections:** 1000
- **Timeout:** 1s
- **Delays:** None
- **Use case:** Maximum speed, local networks only

**Warning:** T4 and T5 may:
- Trigger security alerts
- Crash weak targets
- Violate acceptable use policies

---

## Resource Requirements

### CPU Requirements

| Workload | CPU Cores | Notes |
|----------|-----------|-------|
| **Single host** | 1 core | Minimal CPU usage |
| **Small network (<100)** | 2 cores | Recommended for parallelism |
| **Medium network (100-1K)** | 4 cores | Optimal performance |
| **Large network (1K-10K)** | 8+ cores | Full parallelization |

**CPU Scaling:** R-Map scales linearly with cores up to ~8 cores, then shows diminishing returns.

### Memory Requirements

| Workload | Minimum RAM | Recommended RAM | Notes |
|----------|-------------|-----------------|-------|
| **CLI scans** | 64MB | 128MB | Basic usage |
| **API server** | 128MB | 256MB | REST + WebSocket |
| **Small scans (<100 hosts)** | 256MB | 512MB | Comfortable margin |
| **Medium scans (100-1K)** | 512MB | 1GB | Service detection |
| **Large scans (1K-10K)** | 2GB | 4GB | OS detection + scripts |
| **Massive scans (10K+)** | 4GB | 8GB | Full feature set |

**Memory Optimization:**
- Disable service detection: `-50% memory`
- Disable OS detection: `-30% memory`
- Use streaming output: Constant memory

### Network Requirements

| Parameter | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| **Bandwidth** | 1 Mbps | 10 Mbps | Minimal packet overhead |
| **File descriptors** | 1024 | 4096+ | `ulimit -n 4096` |
| **Ephemeral ports** | 28232-32768 | Full range | Linux default |

**Increase file descriptor limit:**
```bash
# Temporary (current session)
ulimit -n 65536

# Permanent (/etc/security/limits.conf)
* soft nofile 65536
* hard nofile 65536
```

### Disk Requirements

| Component | Space Required | Notes |
|-----------|----------------|-------|
| **Binary** | 10-15MB | Optimized Rust binary |
| **Scan results (JSON)** | 1KB - 10MB | Depends on targets |
| **SQLite database** | Variable | Grows with scans |
| **Logs** | 10MB - 100MB | Rotate logs regularly |

---

## Scaling Recommendations

### Small Deployments (1-10 hosts)

**Configuration:**
```bash
rmap example.com \
  --ports 1-1000 \
  --max-connections 100 \
  --timeout 3 \
  --service-detection
```

**Resources:**
- **CPU:** 1-2 cores
- **RAM:** 256MB
- **Duration:** 5-30 seconds

### Medium Deployments (10-1000 hosts)

**Configuration:**
```bash
rmap 192.168.1.0/24 \
  --fast \
  --max-connections 200 \
  --timeout 3 \
  --service-detection \
  --timing aggressive
```

**Resources:**
- **CPU:** 4 cores
- **RAM:** 1GB
- **Duration:** 1-5 minutes

### Large Deployments (1K-10K hosts)

**Configuration:**
```bash
rmap 10.0.0.0/16 \
  --fast \
  --max-connections 500 \
  --timeout 2 \
  --skip-ping \
  --timing aggressive
```

**Resources:**
- **CPU:** 8 cores
- **RAM:** 4GB
- **Duration:** 10-60 minutes

**Optimization tips:**
- Use `--skip-ping` for large ranges
- Disable service detection initially
- Run OS detection separately
- Stream results to SQLite

### Massive Deployments (10K+ hosts)

**Distributed architecture required:**

```bash
# Split into chunks
rmap 10.0.0.0/17 --output chunk1.json &
rmap 10.0.128.0/17 --output chunk2.json &

# Or use Kubernetes for horizontal scaling
kubectl scale deployment rmap --replicas=10
```

**Resources (per instance):**
- **CPU:** 4-8 cores
- **RAM:** 2-4GB
- **Duration:** 1-4 hours

---

## Optimization Strategies

### 1. Port Range Optimization

**Problem:** Scanning all 65,535 ports takes too long.

**Solutions:**
```bash
# Option A: Fast mode (top 100 ports)
rmap example.com --fast

# Option B: Common ports only
rmap example.com -p 21-23,25,80,110,143,443,3306,5432,8080

# Option C: Service-specific
rmap example.com -p 80,443,8000-9000  # Web services
rmap example.com -p 3306,5432,1433,27017  # Databases
```

**Impact:** Reducing from 65K to 100 ports = **650x faster**

### 2. Service Detection Optimization

**Problem:** Service detection (banner grabbing) is slow.

**Solutions:**
```bash
# Disable for fast recon
rmap 192.168.1.0/24 --fast

# Run in two phases
# Phase 1: Port discovery
rmap 192.168.1.0/24 --fast -o ports.json

# Phase 2: Service detection on open ports
rmap 192.168.1.1 -p 80,443,22 --service-detection
```

**Impact:** Disabling `-sV` = **2-5x faster**

### 3. OS Detection Optimization

**Problem:** Active OS fingerprinting requires multiple probe packets.

**Solutions:**
```bash
# Use passive OS detection (faster)
rmap example.com --os-detect --passive

# Or combine with service detection
rmap example.com -p 80,443 -sV --os-detect
# (HTTP headers give OS hints)
```

**Impact:** Passive detection = **10x faster** than active

### 4. DNS Resolution Optimization

**Problem:** Reverse DNS lookups add latency.

**Solutions:**
```bash
# Skip DNS entirely for speed
rmap 192.168.1.0/24 --no-dns

# Or cache DNS results
rmap 192.168.1.0/24 --dns-cache
```

**Impact:** Disabling DNS = **20-50% faster** on large networks

### 5. Parallel Scanning Optimization

**Problem:** Default concurrency too low for large networks.

**Solutions:**
```bash
# Increase concurrency for large scans
rmap 10.0.0.0/16 --max-connections 500

# But monitor system resources
rmap 10.0.0.0/16 --max-connections 500 --monitor
```

**Impact:** 500 connections vs 100 = **3-5x faster**

### 6. Output Format Optimization

**Problem:** Some output formats are slow to generate.

**Solutions:**
```bash
# Fast: JSON or grepable
rmap example.com --format json

# Slow: HTML or PDF
rmap example.com --format html  # Generate after scan
```

**Impact:** JSON vs PDF = **10x faster** output generation

---

## Benchmarking

### Run Built-in Benchmarks

```bash
# Full benchmark suite (10 iterations)
cd benchmarks/scripts
./run_benchmarks.sh

# Quick test (1 iteration)
./quick_benchmark.sh

# View results
cat ../results/SUMMARY_*.md
```

### Custom Benchmark

```bash
# Measure scan time
time rmap example.com -p 1-1000

# Measure with statistics
/usr/bin/time -v rmap example.com -p 1-1000
```

**Key metrics to track:**
- **Elapsed time:** Wall-clock duration
- **User CPU time:** CPU spent in user space
- **System CPU time:** CPU spent in kernel (syscalls)
- **Maximum RSS:** Peak memory usage
- **File descriptors:** Open sockets

### Profiling

```bash
# CPU profiling (requires cargo-flamegraph)
cargo install flamegraph
cargo build --release
sudo flamegraph ./target/release/rmap example.com -p 1-1000

# Memory profiling (requires valgrind)
valgrind --tool=massif ./target/release/rmap example.com -p 1-1000
ms_print massif.out.*
```

---

## Troubleshooting Performance

### Slow Scans

**Symptoms:** Scan taking much longer than expected.

**Diagnosis:**
```bash
# Check if service detection is enabled
rmap example.com -p 80 -v  # Look for "Service detection: enabled"

# Check timeout settings
rmap example.com -p 80 --timeout 1  # Try faster timeout

# Check concurrency
rmap example.com -p 1-1000 --max-connections 500  # Increase
```

**Common causes:**
1. **High timeout:** Reduce from 30s to 3s
2. **Low concurrency:** Increase from 50 to 500
3. **Service detection:** Disable `-sV` for speed
4. **DNS resolution:** Use `--no-dns`
5. **Network latency:** Check with `ping`

### High Memory Usage

**Symptoms:** R-Map consuming >4GB RAM.

**Diagnosis:**
```bash
# Monitor memory
watch -n 1 'ps aux | grep rmap'

# Check scan size
rmap 10.0.0.0/8 --fast  # This is huge! (16M hosts)

# Reduce target scope
rmap 10.0.0.0/16 --fast  # More reasonable (65K hosts)
```

**Solutions:**
1. **Reduce target count:** Use smaller CIDR blocks
2. **Disable OS detection:** Saves 30% memory
3. **Stream results:** `--format json --output results.jsonl`
4. **Split scans:** Divide into multiple smaller scans

### Connection Timeouts

**Symptoms:** Many "connection timeout" errors.

**Diagnosis:**
```bash
# Test network latency
ping -c 10 example.com

# Check firewall rules
sudo iptables -L -n -v

# Try longer timeout
rmap example.com --timeout 10
```

**Solutions:**
1. **Increase timeout:** `--timeout 10`
2. **Check network path:** `traceroute`
3. **Firewall blocking:** Some ports may be filtered
4. **Target is down:** Use `--skip-ping` to scan anyway

### File Descriptor Exhaustion

**Symptoms:** Error: "Too many open files"

**Diagnosis:**
```bash
# Check current limit
ulimit -n

# Check open files
lsof -p $(pgrep rmap) | wc -l
```

**Solutions:**
```bash
# Increase limit (temporary)
ulimit -n 65536

# Increase limit (permanent)
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Reduce concurrency
rmap example.com --max-connections 100
```

---

## Performance Checklist

### Before Scanning

- [ ] Estimate scan size (hosts × ports)
- [ ] Choose appropriate timing template
- [ ] Set resource limits (`ulimit -n 65536`)
- [ ] Test connectivity (`ping`, `traceroute`)
- [ ] Check firewall rules (egress allowed)

### During Scanning

- [ ] Monitor CPU/memory (`htop`, `top`)
- [ ] Watch for errors in logs
- [ ] Verify progress (WebSocket or verbose mode)
- [ ] Check network bandwidth (`iftop`)

### After Scanning

- [ ] Review scan duration
- [ ] Check result completeness
- [ ] Analyze resource usage
- [ ] Update baseline benchmarks

---

## Performance Best Practices

### DO

✅ **Use timing templates** for common scenarios
✅ **Increase concurrency** for large networks
✅ **Disable DNS** for speed (`--no-dns`)
✅ **Split large scans** into manageable chunks
✅ **Monitor resources** during scans
✅ **Benchmark regularly** to detect regressions

### DON'T

❌ **Use T5 (insane)** on untrusted networks
❌ **Scan entire /8 networks** in one go
❌ **Enable all features** for fast recon
❌ **Ignore timeout errors** (may indicate issues)
❌ **Run without resource limits** (ulimit)
❌ **Forget to rotate logs** (disk space)

---

**Document Version:** 1.0
**Last Updated:** 2025-01-19
**Feedback:** https://github.com/Ununp3ntium115/R-map/issues
