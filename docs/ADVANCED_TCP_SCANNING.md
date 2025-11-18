# Advanced TCP Scanning in R-Map

This document describes the advanced TCP scanning techniques implemented in R-Map, including ACK, FIN, NULL, and Xmas scans.

## Overview

R-Map now supports four advanced TCP scanning techniques that complement the traditional SYN scan:

1. **ACK Scan** - Firewall rule detection
2. **FIN Scan** - Stealth scanning
3. **NULL Scan** - All TCP flags off
4. **Xmas Scan** - FIN+PSH+URG flags set

All advanced TCP scans require raw socket privileges (root/administrator access).

## Implementation Details

### File Structure

- **Location**: `/home/user/R-map/crates/nmap-engine/src/advanced_tcp_scanner.rs`
- **Integration**: Integrated into `ScanEngine` in `lib.rs`
- **Raw Socket Support**: Extended in `/home/user/R-map/crates/nmap-net/src/raw_socket.rs`

### Scanner Types

#### 1. ACK Scanner (`AckScanner`)

**Purpose**: Determine firewall rules and packet filtering behavior

**How it works**:
- Sends TCP packets with only the ACK flag set
- Does NOT determine if ports are open or closed
- Instead, identifies filtered vs. unfiltered ports

**Response Interpretation**:
- **RST response** → Port is **unfiltered** (firewall allows packet through)
- **No response** → Port is **filtered** (firewall is blocking)
- **ICMP unreachable** → Port is **filtered**

**Use Cases**:
- Mapping firewall rules
- Identifying which ports a firewall allows traffic through
- Testing stateful firewall behavior

**Example Usage**:
```rust
use nmap_engine::AckScanner;
use nmap_timing::TimingTemplate;
use nmap_net::Host;

let timing = TimingTemplate::Normal.config();
let scanner = AckScanner::new(timing)?;

let mut hosts = vec![Host::new("192.168.1.1".parse()?)];
let ports = vec![80, 443, 22, 21];

scanner.scan_hosts(&mut hosts, &ports).await?;

// Check results
for host in hosts {
    for port in host.ports {
        match port.state {
            PortState::Unfiltered => println!("Port {} is unfiltered", port.number),
            PortState::Filtered => println!("Port {} is filtered", port.number),
            _ => {}
        }
    }
}
```

#### 2. FIN Scanner (`FinScanner`)

**Purpose**: Stealthy port scanning that may evade some firewalls and IDSs

**How it works**:
- Sends TCP packets with only the FIN flag set
- According to RFC 793, closed ports should respond with RST
- Open ports should silently drop the packet

**Response Interpretation**:
- **RST response** → Port is **closed**
- **No response** → Port is **open|filtered** (could be open, or could be filtered)
- **ICMP unreachable** → Port is **filtered**

**Advantages**:
- More stealthy than SYN scan
- May bypass simple packet filters
- Doesn't complete TCP handshake

**Limitations**:
- Cannot definitively identify open ports (only open|filtered)
- Doesn't work against Windows systems (they violate RFC 793)
- May be blocked by modern firewalls

**Example Usage**:
```rust
use nmap_engine::FinScanner;
use nmap_timing::TimingTemplate;

let timing = TimingTemplate::Sneaky.config(); // Use slow timing for stealth
let scanner = FinScanner::new(timing)?;

let mut hosts = vec![Host::new("10.0.0.1".parse()?)];
let ports = vec![80, 443, 8080];

scanner.scan_hosts(&mut hosts, &ports).await?;
```

#### 3. NULL Scanner (`NullScanner`)

**Purpose**: Ultra-stealthy scanning with no TCP flags set

**How it works**:
- Sends TCP packets with NO flags set (all flags = 0)
- Even more unusual than FIN scan
- Based on RFC 793 behavior

**Response Interpretation**:
- **RST response** → Port is **closed**
- **No response** → Port is **open|filtered**
- **ICMP unreachable** → Port is **filtered**

**Advantages**:
- Very unusual packet, may evade detection
- Simpler than other scans (no flags to track)

**Limitations**:
- Same as FIN scan
- Even less reliable on non-compliant systems

**Example Usage**:
```rust
use nmap_engine::NullScanner;
use nmap_timing::TimingTemplate;

let timing = TimingTemplate::Paranoid.config(); // Maximum stealth
let scanner = NullScanner::new(timing)?;

let mut hosts = vec![Host::new("172.16.0.1".parse()?)];
let ports = vec![22, 23, 3389];

scanner.scan_hosts(&mut hosts, &ports).await?;
```

#### 4. Xmas Scanner (`XmasScanner`)

**Purpose**: Stealthy scanning with unusual flag combination

**How it works**:
- Sends TCP packets with FIN, PSH, and URG flags set
- Name comes from flags being "lit up like a Christmas tree"
- Based on RFC 793 behavior

**Response Interpretation**:
- **RST response** → Port is **closed**
- **No response** → Port is **open|filtered**
- **ICMP unreachable** → Port is **filtered**

**Advantages**:
- Unusual packet signature
- May evade simple filters
- Same benefits as FIN scan

**Limitations**:
- Same as FIN and NULL scans
- More obvious than NULL scan due to multiple flags

**Example Usage**:
```rust
use nmap_engine::XmasScanner;
use nmap_timing::TimingTemplate;

let timing = TimingTemplate::Normal.config();
let scanner = XmasScanner::new(timing)?;

let mut hosts = vec![Host::new("192.168.0.1".parse()?)];
let ports = vec![80, 443];

scanner.scan_hosts(&mut hosts, &ports).await?;
```

## Integration with ScanEngine

The advanced scanners are automatically integrated into the `ScanEngine`:

```rust
use nmap_engine::ScanEngine;
use nmap_core::NmapOptions;
use nmap_net::ScanType;

let mut options = NmapOptions::default();
options.scan_types = vec![ScanType::Ack]; // or Fin, Null, Xmas

let engine = ScanEngine::new(&options)?;

// Scanners are automatically selected based on scan type
let results = engine.port_scan(&targets).await?;
```

## Technical Implementation

### Raw Socket Methods

The following methods were added to `RawSocket`:

- `send_ack_packet()` - Send ACK packet
- `send_fin_packet()` - Send FIN packet
- `send_null_packet()` - Send NULL packet (no flags)
- `send_xmas_packet()` - Send Xmas packet (FIN+PSH+URG)

### Packet Crafting

All packets are crafted using the `pnet` library:

```rust
fn craft_tcp_packet(
    source_ip: IpAddr,
    dest_ip: IpAddr,
    source_port: u16,
    dest_port: u16,
    flags: u8,
) -> Result<Vec<u8>>
```

### Response Handling

All scanners use the common `TcpResponse` structure:

```rust
pub struct TcpResponse {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub dest_port: u16,
    pub flags: u8,
    pub sequence: u32,
    pub acknowledgement: u32,
}
```

Helper methods:
- `is_rst()` - Check if RST flag is set
- `is_syn_ack()` - Check if SYN+ACK flags are set

## Testing

### Unit Tests

Each scanner includes comprehensive unit tests:

```bash
# Run all tests
cargo test

# Run specific scanner tests
cargo test ack_scanner
cargo test fin_scanner
cargo test null_scanner
cargo test xmas_scanner
```

### Test Coverage

Tests included in `advanced_tcp_scanner.rs`:
- Scanner creation tests
- Response interpretation tests
- Port state validation tests
- Integration tests for each scan type

## Performance Considerations

### Timing Profiles

All scanners support standard timing profiles:

| Profile | Scan Delay | Max RTT Timeout | Use Case |
|---------|------------|-----------------|----------|
| Paranoid (T0) | 5 seconds | 300 seconds | Maximum stealth, IDS evasion |
| Sneaky (T1) | 15 seconds | 15 seconds | IDS evasion |
| Polite (T2) | 400 ms | 10 seconds | Reduced bandwidth |
| Normal (T3) | 0 ms | 10 seconds | Default timing |
| Aggressive (T4) | 0 ms | 1.25 seconds | Fast, reliable networks |
| Insane (T5) | 0 ms | 300 ms | Very fast, may miss results |

### Rate Limiting

All scanners implement:
- Per-probe rate limiting
- Per-host rate limiting
- Configurable delays based on timing profile

## Security Considerations

### Privilege Requirements

All advanced TCP scans require:
- **Linux/Unix**: Root privileges or CAP_NET_RAW capability
- **Windows**: Administrator privileges

Without privileges, scans fall back to TCP connect scan.

### Detection Evasion

Stealth levels (most to least stealthy):
1. **NULL scan** - No flags, very unusual
2. **FIN scan** - Single flag, stealthier than SYN
3. **Xmas scan** - Multiple flags, unusual pattern
4. **ACK scan** - Single flag, used for firewall mapping

### Legal Considerations

⚠️ **WARNING**: Only scan networks and systems you have permission to test.

- Unauthorized scanning may be illegal
- Advanced scans may trigger IDS/IPS alerts
- Some scans may be considered more aggressive than others

## Limitations

### FIN/NULL/Xmas Scans

1. **Windows Systems**: Do not follow RFC 793, respond differently
2. **Stateful Firewalls**: May block these packets
3. **Modern IDS**: Will likely detect these scans
4. **Ambiguous Results**: Cannot definitively identify open ports

### ACK Scans

1. **Limited Information**: Only shows filtered vs. unfiltered
2. **Stateful Firewalls**: May produce confusing results
3. **No Open/Closed Info**: Doesn't determine actual port state

## Comparison with Nmap

R-Map's implementation matches Nmap's behavior:

| Feature | Nmap Flag | R-Map ScanType |
|---------|-----------|----------------|
| ACK Scan | -sA | ScanType::Ack |
| FIN Scan | -sF | ScanType::Fin |
| NULL Scan | -sN | ScanType::Null |
| Xmas Scan | -sX | ScanType::Xmas |

## Future Enhancements

Potential improvements:
- Window scan (-sW)
- Maimon scan (-sM)
- ICMP response handling
- Parallel scanning optimization
- Custom flag combinations

## References

- RFC 793: Transmission Control Protocol
- Nmap Network Scanning Guide
- TCP/IP Illustrated, Volume 1

## Code Files

**Implementation**:
- `/home/user/R-map/crates/nmap-engine/src/advanced_tcp_scanner.rs`
- `/home/user/R-map/crates/nmap-net/src/raw_socket.rs`

**Integration**:
- `/home/user/R-map/crates/nmap-engine/src/lib.rs`

**Types**:
- `/home/user/R-map/crates/nmap-net/src/scan_types.rs`

## License

Same as R-Map project: MIT OR Apache-2.0
