# R-Map Benchmark Test Targets

This directory contains target host lists for performance benchmarking R-Map against nmap.

## Target Files

### 1. single-host.txt
- **Hosts:** 1 (localhost)
- **Purpose:** Quick tests, baseline latency measurements
- **Use Cases:**
  - Development testing
  - Quick validation
  - Minimal resource usage

### 2. small-network.txt
- **Hosts:** 10 IPs (192.168.1.1-10)
- **Purpose:** Small network scans
- **Use Cases:**
  - Network sweep tests
  - Service detection on multiple hosts
  - Realistic small office scenarios

### 3. medium-network.txt
- **Hosts:** 100 IPs (10.0.0.1-100)
- **Purpose:** Medium-scale network testing
- **Use Cases:**
  - Departmental network simulations
  - Parallel scanning performance
  - Scalability validation

### 4. large-network.txt
- **Hosts:** 1000 IPs (172.16.0.1-1000)
- **Purpose:** Large-scale stress testing
- **Use Cases:**
  - Enterprise network simulations
  - Maximum throughput testing
  - Resource usage under load
  - Regression testing for performance

## Test Scenarios Using These Targets

### TC-001 to TC-005: Single Host Tests
These scenarios use `localhost` or `127.0.0.1` for focused performance testing:
- TC-001: Top 100 ports
- TC-002: Custom ports
- TC-003: Service detection
- TC-004: Port range 1-1000
- TC-005: Extended range 1-10000

### TC-006 to TC-007: Small Network Tests
Uses `small-network.txt` (10 hosts):
- TC-006: Fast scan across 10 hosts
- TC-007: Service detection on 10 hosts
- TC-009: Stress test with large port range

### TC-008: Medium Network Test
Uses `medium-network.txt` (100 hosts):
- TC-008: Fast scan across 100 hosts

### TC-010: Large Network Test
Uses `large-network.txt` (1000 hosts):
- TC-010: Fast scan across 1000 simulated hosts

## Usage Examples

### Direct nmap usage:
```bash
nmap -iL small-network.txt --top-ports 100 -n -T4
```

### Direct R-Map usage:
```bash
rmap --fast -n -iL small-network.txt
```

### Via benchmark scripts:
```bash
cd /home/user/R-map/benchmarks/scripts
./run_benchmarks.sh  # Runs all 10 scenarios automatically
```

## Notes

- **IP Ranges:** The IPs in these files are private/simulated addresses
- **Real Networks:** For production testing, replace with actual target IPs
- **Permissions:** Ensure you have authorization before scanning real networks
- **Performance:** Larger target files will significantly increase scan time
- **Customization:** You can create your own target files following the same format

## File Format

Each target file contains one IP address per line:
```
192.168.1.1
192.168.1.2
192.168.1.3
...
```

## Generating Custom Targets

### Python example:
```python
# Generate 50 IPs in 10.10.x.x range
for i in range(1, 51):
    print(f"10.10.{i//256}.{i%256}")
```

### Bash example:
```bash
# Generate IPs from CIDR notation
nmap -sL 192.168.1.0/24 -n | grep "Nmap scan report" | awk '{print $5}'
```

## Integration with Benchmarks

The benchmark suite automatically uses these targets via the `-iL` flag:
- Reads target list from file
- Runs scans against all listed hosts
- Aggregates results across all targets
- Measures total time and per-host performance

See `/home/user/R-map/benchmarks/scripts/run_benchmarks.sh` for implementation details.
