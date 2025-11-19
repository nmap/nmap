# R-Map Troubleshooting Guide

**Version:** 1.0.0
**Last Updated:** 2025-01-19

## Table of Contents

- [Installation Issues](#installation-issues)
- [Permission Errors](#permission-errors)
- [Network Connectivity](#network-connectivity)
- [Performance Problems](#performance-problems)
- [Scan Errors](#scan-errors)
- [API Server Issues](#api-server-issues)
- [Docker Problems](#docker-problems)
- [Kubernetes Issues](#kubernetes-issues)
- [Common Error Messages](#common-error-messages)
- [Getting Help](#getting-help)

---

## Installation Issues

### Cannot Install - Rust Version Too Old

**Error:**
```
error: package `rmap v1.0.0` cannot be built because it requires rustc 1.70 or newer
```

**Solution:**
```bash
# Update Rust to latest stable
rustup update stable

# Verify version
rustc --version  # Should be 1.70+
```

### Build Fails - Missing Dependencies

**Error:**
```
error: linker `cc` not found
```

**Solution (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev
```

**Solution (Fedora/RHEL):**
```bash
sudo dnf install gcc gcc-c++ openssl-devel
```

**Solution (macOS):**
```bash
xcode-select --install
```

### Build Fails - Out of Memory

**Error:**
```
error: could not compile `rmap`
Killed
```

**Solution:**
```bash
# Reduce parallel compilation jobs
cargo build --release -j 2

# Or add swap space
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Binary Not Found After Install

**Error:**
```bash
$ rmap
bash: rmap: command not found
```

**Solution:**
```bash
# Check if binary installed
cargo install --list

# Add cargo bin to PATH
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Or use full path
~/.cargo/bin/rmap --version
```

---

## Permission Errors

### SYN Scan Requires Root

**Error:**
```
Error: SYN scan requires root privileges
Permission denied (os error 13)
```

**Solution:**
```bash
# Run with sudo
sudo rmap example.com --scan syn -p 80,443

# Or set capabilities (Linux only, more secure)
sudo setcap cap_net_raw,cap_net_admin+eip $(which rmap)
rmap example.com --scan syn -p 80,443  # Now works without sudo
```

**Warning:** Setting capabilities allows non-root SYN scanning but may have security implications.

### Cannot Bind to Port 80/443

**Error:**
```
Error: Address already in use (os error 98)
```

**Solutions:**
```bash
# Option 1: Stop conflicting service
sudo systemctl stop apache2  # or nginx

# Option 2: Use different port
rmap-api --port 8080

# Option 3: Use sudo (not recommended)
sudo rmap-api --port 80
```

### Raw Socket Permission Denied

**Error:**
```
Error: Operation not permitted (os error 1)
```

**Solutions:**
```bash
# Option 1: Use sudo (quick fix)
sudo rmap example.com --scan syn

# Option 2: Set capabilities (permanent, secure)
sudo setcap cap_net_raw+eip $(which rmap)

# Option 3: Use TCP Connect scan (no root needed)
rmap example.com --scan connect  # Default, no sudo required
```

### File Permission Denied

**Error:**
```
Error: Permission denied (os error 13)
File: /var/log/rmap.log
```

**Solutions:**
```bash
# Check file permissions
ls -l /var/log/rmap.log

# Fix permissions
sudo chown $USER:$USER /var/log/rmap.log
sudo chmod 644 /var/log/rmap.log

# Or write to user-writable location
rmap example.com --log-file ~/rmap.log
```

---

## Network Connectivity

### Target Unreachable

**Error:**
```
Error: No route to host (os error 113)
```

**Diagnosis:**
```bash
# Test basic connectivity
ping example.com

# Check routing
ip route get example.com

# Test specific port
telnet example.com 80
```

**Solutions:**
1. **Target is down:** Check if host is online
2. **Network issue:** Check gateway, DNS, firewall
3. **SSRF protection:** R-Map blocks certain IPs (see below)

### SSRF Protection Blocking Target

**Error:**
```
Error: Target blocked by SSRF protection
Target '169.254.169.254' is a cloud metadata endpoint
```

**Explanation:** R-Map blocks private/metadata IPs by default for security.

**Blocked ranges:**
- `127.0.0.0/8` (loopback)
- `169.254.169.254` (cloud metadata)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (private)
- `224.0.0.0/4` (multicast)

**Solutions:**
```bash
# This is intentional for security
# If you REALLY need to scan these:

# Option 1: Use --allow-private (if implemented)
rmap 192.168.1.1 --allow-private

# Option 2: Disable SSRF protection (DANGEROUS!)
rmap 169.254.169.254 --disable-ssrf-protection

# Option 3: Use nmap instead for these ranges
nmap 127.0.0.1
```

**Warning:** Disabling SSRF protection is a security risk!

### DNS Resolution Failures

**Error:**
```
Error: failed to lookup address information
Name or service not known
```

**Diagnosis:**
```bash
# Test DNS resolution
nslookup example.com
dig example.com

# Check /etc/resolv.conf
cat /etc/resolv.conf
```

**Solutions:**
```bash
# Use IP address directly
rmap 93.184.216.34

# Skip DNS resolution
rmap example.com --no-dns

# Use custom DNS server (if implemented)
rmap example.com --dns-server 8.8.8.8
```

### Connection Timeout

**Error:**
```
Error: Connection timed out (os error 110)
```

**Diagnosis:**
```bash
# Check network latency
ping -c 5 example.com

# Test port directly
nc -zv example.com 80
```

**Solutions:**
```bash
# Increase timeout
rmap example.com --timeout 10

# Check if firewall is blocking
sudo iptables -L -n -v

# Try different scan type
rmap example.com --scan connect  # Sometimes works better
```

### Firewall Blocking Outbound

**Error:**
```
Error: Connection refused (os error 111)
```

**Diagnosis:**
```bash
# Check outbound firewall rules
sudo iptables -L OUTPUT -n -v

# Check if port is allowed
telnet example.com 80
```

**Solutions:**
```bash
# Allow outbound traffic (temporary)
sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT

# Or disable firewall (testing only!)
sudo iptables -F

# Use allowed ports only
rmap example.com -p 80,443  # Usually allowed
```

---

## Performance Problems

### Scan Too Slow

**Problem:** Scan taking hours instead of minutes.

**Diagnosis:**
```bash
# Run with verbose output
rmap example.com -p 1-1000 -v

# Check resource usage
htop  # Look for CPU, memory usage
```

**Solutions:**
```bash
# 1. Increase concurrency
rmap example.com -p 1-1000 --max-connections 500

# 2. Reduce timeout
rmap example.com -p 1-1000 --timeout 2

# 3. Use faster timing template
rmap example.com -p 1-1000 --timing aggressive

# 4. Disable service detection (if enabled)
rmap example.com -p 1-1000  # No -sV

# 5. Skip DNS resolution
rmap example.com -p 1-1000 --no-dns

# 6. Use fast mode
rmap example.com --fast
```

### High Memory Usage

**Problem:** R-Map consuming >4GB RAM.

**Diagnosis:**
```bash
# Monitor memory in real-time
watch -n 1 'ps aux | grep rmap | head -1'

# Check scan size
# How many targets × ports are you scanning?
```

**Solutions:**
```bash
# 1. Reduce scan scope
rmap 10.0.0.0/24 --fast  # Instead of /16

# 2. Disable OS detection
rmap 10.0.0.0/24 --fast  # No --os-detect

# 3. Stream results instead of buffering
rmap 10.0.0.0/24 --format json --output results.json

# 4. Split into smaller scans
rmap 10.0.0.0/25 -o part1.json
rmap 10.0.128.0/25 -o part2.json
```

### CPU at 100%

**Problem:** R-Map using all CPU cores.

**Explanation:** This is often expected for large scans!

**Solutions (if unwanted):**
```bash
# Limit CPU usage (Linux)
cpulimit -l 50 -p $(pgrep rmap)

# Or use nice to lower priority
nice -n 19 rmap example.com -p 1-65535

# Reduce concurrency
rmap example.com --max-connections 50  # Less CPU
```

### File Descriptor Limit

**Error:**
```
Error: Too many open files (os error 24)
```

**Diagnosis:**
```bash
# Check current limit
ulimit -n

# Check open files
lsof -p $(pgrep rmap) | wc -l
```

**Solutions:**
```bash
# Temporary fix (current shell)
ulimit -n 65536

# Permanent fix (add to /etc/security/limits.conf)
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Then logout and login again

# Or reduce concurrency
rmap example.com --max-connections 500  # Uses ~500 FDs
```

---

## Scan Errors

### Target Validation Failed

**Error:**
```
Error: Invalid target specification
Target '999.999.999.999' is not a valid IP address
```

**Solutions:**
```bash
# Check your target format
rmap 192.168.1.1      # Valid IP
rmap example.com      # Valid hostname
rmap 192.168.1.0/24   # Valid CIDR

# Invalid examples:
rmap 999.999.999.999  # Invalid IP
rmap example          # Incomplete hostname
rmap 192.168.1.1/33   # Invalid CIDR (max /32)
```

### Port Range Invalid

**Error:**
```
Error: Invalid port specification
Port range '70000' exceeds maximum port number (65535)
```

**Solutions:**
```bash
# Valid port ranges
rmap example.com -p 80              # Single port
rmap example.com -p 80,443          # Multiple ports
rmap example.com -p 80-100          # Port range
rmap example.com -p 1-65535         # All ports

# Invalid examples:
rmap example.com -p 70000           # Port too high
rmap example.com -p 0               # Port 0 invalid
rmap example.com -p 100-80          # Reverse range
```

### Service Detection Failure

**Error:**
```
Warning: Service detection failed for port 80
Timeout reading banner
```

**Explanation:** Service may not send a banner, or timeout too short.

**Solutions:**
```bash
# Increase timeout for banner reading
rmap example.com -p 80 -sV --timeout 10

# Try manual banner grab
telnet example.com 80
# Type: GET / HTTP/1.0
# Press Enter twice

# Some services don't send banners (normal)
# HTTP/HTTPS require valid requests
```

### OS Detection Failure

**Error:**
```
Warning: OS detection failed
Insufficient data for fingerprinting
```

**Causes:**
1. **Firewall blocking probes:** Target filters packets
2. **No open ports:** Need at least 1 open port
3. **Incomplete response:** Target didn't respond to all probes

**Solutions:**
```bash
# Ensure at least one open port
rmap example.com -p 80 --os-detect

# Combine with service detection
rmap example.com -p 80 -sV --os-detect

# Use passive OS detection (less reliable but stealthier)
rmap example.com --os-detect --passive
```

---

## API Server Issues

### API Server Won't Start

**Error:**
```
Error: Address already in use (os error 98)
```

**Diagnosis:**
```bash
# Check if port 8080 is in use
lsof -i :8080
# or
netstat -tulpn | grep 8080
```

**Solutions:**
```bash
# Stop conflicting process
sudo kill $(lsof -t -i:8080)

# Or use different port
rmap-api --port 8081

# Check if another rmap instance is running
ps aux | grep rmap
```

### Cannot Connect to API

**Error:**
```
curl: (7) Failed to connect to localhost port 8080: Connection refused
```

**Diagnosis:**
```bash
# Check if API server is running
ps aux | grep rmap-api

# Check listening ports
netstat -tulpn | grep 8080

# Check logs
journalctl -u rmap-api -f  # If using systemd
```

**Solutions:**
```bash
# Start the API server
rmap-api &

# Check firewall
sudo iptables -L -n | grep 8080

# Verify server is listening
curl http://localhost:8080/api/v1/health
```

### Authentication Failed

**Error:**
```json
{
  "error": "Invalid credentials"
}
```

**Solutions:**
```bash
# Register a new user
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'

# Login to get token
TOKEN=$(curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  | jq -r '.token')

# Use token in requests
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/scans
```

### WebSocket Connection Drops

**Error:**
```
WebSocket closed unexpectedly
```

**Causes:**
1. **Token expired:** Tokens expire after 1 hour
2. **Network timeout:** Long idle connections
3. **Server restart:** API server restarted

**Solutions:**
```javascript
// Implement reconnection logic
const connectWebSocket = () => {
  const ws = new WebSocket(url);

  ws.onclose = () => {
    console.log('Reconnecting in 5s...');
    setTimeout(connectWebSocket, 5000);
  };

  return ws;
};
```

---

## Docker Problems

### Cannot Pull Docker Image

**Error:**
```
Error response from daemon: pull access denied for ghcr.io/ununp3ntium115/r-map
```

**Solutions:**
```bash
# Login to GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Or use public image (if available)
docker pull ghcr.io/ununp3ntium115/r-map:latest

# Build locally
git clone https://github.com/Ununp3ntium115/R-map.git
cd R-map
docker build -t rmap:local .
```

### Docker Container Exits Immediately

**Error:**
```
$ docker ps
CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS
(empty)
```

**Diagnosis:**
```bash
# Check container logs
docker logs <container_id>

# Run interactively to see errors
docker run --rm -it ghcr.io/ununp3ntium115/r-map:latest --help
```

**Common causes:**
1. **No command provided:** Container needs a scan target
2. **Invalid arguments:** Check syntax
3. **Permission issues:** SYN scans need `--cap-add=NET_RAW`

**Solutions:**
```bash
# Provide scan target
docker run --rm ghcr.io/ununp3ntium115/r-map:latest scanme.nmap.org -p 80

# For SYN scans, add capabilities
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
  ghcr.io/ununp3ntium115/r-map:latest \
  scanme.nmap.org --scan syn -p 80
```

### Docker Compose Fails

**Error:**
```
ERROR: yaml.scanner.ScannerError: mapping values are not allowed here
```

**Diagnosis:**
```bash
# Validate docker-compose.yml syntax
docker-compose config
```

**Solutions:**
```bash
# Check YAML indentation (use spaces, not tabs)
# Fix syntax errors
# Ensure proper formatting

# Update Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

---

## Kubernetes Issues

### Pod CrashLoopBackOff

**Error:**
```
$ kubectl get pods
NAME                    READY   STATUS             RESTARTS   AGE
rmap-7d8f6b5c4d-x7k2p   0/1     CrashLoopBackOff   5          3m
```

**Diagnosis:**
```bash
# Check pod logs
kubectl logs rmap-7d8f6b5c4d-x7k2p

# Describe pod for events
kubectl describe pod rmap-7d8f6b5c4d-x7k2p
```

**Common causes:**
1. **Image pull failure:** Check image name and credentials
2. **Resource limits:** Pod OOMKilled (out of memory)
3. **Config error:** Invalid environment variables
4. **Liveness probe failing:** Health check failing

**Solutions:**
```bash
# Check image pull
kubectl describe pod <pod-name> | grep -A 5 Events

# Increase memory limits
kubectl edit deployment rmap
# Change: memory: "512Mi" to "2Gi"

# Disable liveness probe temporarily
kubectl edit deployment rmap
# Comment out livenessProbe section
```

### Service Not Reachable

**Error:**
```
curl: (7) Failed to connect to rmap.example.com port 80: Connection refused
```

**Diagnosis:**
```bash
# Check service
kubectl get svc rmap

# Check endpoints
kubectl get endpoints rmap

# Check ingress
kubectl get ingress rmap
```

**Solutions:**
```bash
# Port forward to test directly
kubectl port-forward svc/rmap 8080:8080
curl http://localhost:8080/api/v1/health

# Check service selector matches pod labels
kubectl get pods --show-labels
kubectl get svc rmap -o yaml | grep selector

# Recreate service
kubectl delete svc rmap
kubectl apply -f rmap-service.yaml
```

### Persistent Volume Issues

**Error:**
```
Warning  FailedMount  Pod  MountVolume.SetUp failed for volume "rmap-data"
```

**Diagnosis:**
```bash
# Check PV and PVC status
kubectl get pv
kubectl get pvc

# Describe PVC
kubectl describe pvc rmap-data
```

**Solutions:**
```bash
# Delete and recreate PVC
kubectl delete pvc rmap-data
kubectl apply -f rmap-pvc.yaml

# Use emptyDir for testing
# Edit deployment and change volume type to emptyDir
```

---

## Common Error Messages

### "Command not found"

**Problem:** `rmap` command not in PATH

**Fix:**
```bash
# Find binary location
which rmap
# or
find ~ -name rmap -type f 2>/dev/null

# Add to PATH
export PATH="$HOME/.cargo/bin:$PATH"
```

### "SSL certificate problem"

**Problem:** Invalid or expired TLS certificate

**Fix:**
```bash
# Update CA certificates
sudo update-ca-certificates

# Or skip verification (NOT recommended)
rmap https://expired.badssl.com --insecure
```

### "Invalid JSON output"

**Problem:** JSON output is malformed

**Fix:**
```bash
# Validate JSON
rmap example.com --format json | jq .

# If invalid, file a bug report
# Include exact command and output
```

### "Scan cancelled by user"

**Problem:** Pressed Ctrl+C during scan

**Fix:**
```bash
# This is normal - scan was interrupted
# Results up to cancellation point are saved (if using --output)

# Resume from where you left off (if supported)
rmap example.com --resume scan_id
```

---

## Getting Help

### Debugging Mode

Enable verbose logging:
```bash
# Verbose output
rmap example.com -v

# Very verbose
rmap example.com -vv

# Debug logs
RUST_LOG=debug rmap example.com

# Trace logs (very detailed)
RUST_LOG=trace rmap example.com
```

### Collect Diagnostic Info

```bash
# System info
uname -a
rustc --version
cargo --version

# R-Map version
rmap --version

# Network test
ping -c 3 example.com
traceroute example.com

# Resource limits
ulimit -a

# Save logs
RUST_LOG=debug rmap example.com > rmap-debug.log 2>&1
```

### Reporting Bugs

When filing a GitHub issue, include:

1. **R-Map version:** `rmap --version`
2. **Operating system:** `uname -a`
3. **Rust version:** `rustc --version`
4. **Command used:** Exact command line
5. **Error message:** Full error output
6. **Expected behavior:** What should happen
7. **Debug logs:** `RUST_LOG=debug rmap ...`

### Community Support

- **GitHub Issues:** https://github.com/Ununp3ntium115/R-map/issues
- **Discussions:** https://github.com/Ununp3ntium115/R-map/discussions
- **Documentation:** https://docs.r-map.io (coming soon)

### Professional Support

For enterprise support, contact: support@r-map.io

---

**Document Version:** 1.0
**Last Updated:** 2025-01-19
**Feedback:** https://github.com/Ununp3ntium115/R-map/issues
