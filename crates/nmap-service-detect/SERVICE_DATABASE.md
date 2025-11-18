# R-Map Service Detection Database

## Overview

This document describes the comprehensive service detection signature database implemented in R-Map's service detection module. The database contains **103+ service signatures** covering a wide range of protocols and services commonly found in network environments.

## Database Statistics

- **Total Signatures**: 103+
- **Total Probes**: 40+
- **Protocols Supported**: TCP, UDP
- **Categories**: 10+ major service categories

## Service Categories

### 1. Web Servers (11 services)

Modern web servers and application servers:

| Service | Product | Default Ports | Detection Method |
|---------|---------|---------------|------------------|
| HTTP | Generic HTTP Server | 80, 8080, 8000 | HTTP response headers |
| Apache | Apache HTTP Server | 80, 8080, 443 | Server header pattern |
| Nginx | Nginx | 80, 8080, 443 | Server header pattern |
| IIS | Microsoft IIS | 80, 443 | Server header pattern |
| Tomcat | Apache Tomcat | 8080, 8009, 8443 | Apache-Coyote header |
| Jetty | Eclipse Jetty | 8080, 8443 | Server header pattern |
| Lighttpd | Lighttpd | 80, 8080, 443 | Server header pattern |
| Node.js | Node.js/Express | 3000, 8080, 8000 | X-Powered-By header |
| Gunicorn | Gunicorn | 8000, 8080 | Server header pattern |
| Caddy | Caddy Web Server | 80, 443, 2015 | Server header pattern |
| Uvicorn | Uvicorn ASGI | 8000, 8080 | Server header pattern |

**Detection Techniques**:
- HTTP GET requests
- Server header analysis
- Banner pattern matching
- Version extraction from headers

### 2. Databases (15 services)

Relational and NoSQL databases:

| Service | Product | Default Ports | Detection Method |
|---------|---------|---------------|------------------|
| MySQL | MySQL Server | 3306 | Connection handshake |
| PostgreSQL | PostgreSQL | 5432 | Startup message |
| MongoDB | MongoDB | 27017-27019 | Wire protocol |
| Redis | Redis | 6379 | INFO command response |
| Memcached | Memcached | 11211 | VERSION command |
| Elasticsearch | Elasticsearch | 9200, 9300 | REST API response |
| CouchDB | Apache CouchDB | 5984 | JSON API response |
| Cassandra | Apache Cassandra | 9042, 9160 | CQL protocol |
| InfluxDB | InfluxDB | 8086 | HTTP header detection |
| MariaDB | MariaDB | 3306 | Version string |
| Oracle | Oracle Database | 1521, 1526 | TNS protocol |
| MSSQL | Microsoft SQL Server | 1433, 1434 | TDS protocol |
| Neo4j | Neo4j Graph Database | 7474, 7687 | HTTP API |
| RethinkDB | RethinkDB | 28015, 29015 | Protocol detection |
| SQLite | SQLite | N/A | Network wrapper detection |

**Detection Techniques**:
- Protocol-specific handshakes
- Banner grabbing
- Command responses (INFO, VERSION)
- REST API queries
- Version string extraction

### 3. SSH & Remote Access (10 services)

Remote access and terminal services:

| Service | Product | Default Ports | Detection Method |
|---------|---------|---------------|------------------|
| SSH | Generic SSH | 22 | Protocol banner |
| OpenSSH | OpenSSH | 22 | SSH-2.0 banner |
| Dropbear | Dropbear SSH | 22 | SSH banner pattern |
| Telnet | Telnet Server | 23 | IAC negotiation |
| RDP | Microsoft Terminal Services | 3389 | RDP handshake |
| VNC | VNC Server | 5900-5902 | RFB protocol |
| RealVNC | RealVNC | 5900 | RFB banner |
| TightVNC | TightVNC | 5900 | RFB banner |
| X11 | X11 Server | 6000-6002 | X protocol |
| TeamViewer | TeamViewer | 5938 | Protocol detection |

**Detection Techniques**:
- SSH banner exchange
- RFB protocol detection
- Telnet IAC sequences
- RDP connection request
- Protocol version detection

### 4. File Servers (10 services)

File sharing and transfer protocols:

| Service | Product | Default Ports | Detection Method |
|---------|---------|---------------|------------------|
| FTP | Generic FTP | 21 | 220 banner |
| vsftpd | vsftpd | 21 | Banner pattern |
| ProFTPD | ProFTPD | 21 | Banner pattern |
| Pure-FTPd | Pure-FTPd | 21 | Banner pattern |
| FileZilla | FileZilla Server | 21 | Banner pattern |
| SMB | Samba/Windows SMB | 139, 445 | SMB protocol |
| SMB | Microsoft Windows SMB | 139, 445 | SMB protocol |
| TFTP | TFTP Server | 69 | TFTP protocol (UDP) |
| NFS | Network File System | 2049 | RPC NULL request |
| AFP | Apple Filing Protocol | 548 | AFP protocol |

**Detection Techniques**:
- FTP banner analysis
- SMB protocol negotiation
- NFS RPC calls
- TFTP read requests
- AFP handshake

### 5. Mail Servers (8 services)

Email transfer and delivery services:

| Service | Product | Default Ports | Detection Method |
|---------|---------|---------------|------------------|
| SMTP | Generic SMTP | 25, 587, 465 | EHLO response |
| Postfix | Postfix | 25, 587 | Banner pattern |
| Sendmail | Sendmail | 25, 587 | Banner pattern |
| Exim | Exim | 25, 587 | Banner pattern |
| Exchange | Microsoft Exchange | 25, 587 | ESMTP banner |
| IMAP | Generic IMAP | 143, 993 | CAPABILITY response |
| Dovecot | Dovecot | 143, 993 | Banner pattern |
| Courier | Courier IMAP | 143, 993 | Banner pattern |
| Cyrus | Cyrus IMAP | 143, 993 | Banner pattern |
| POP3 | POP3 Server | 110, 995 | +OK response |
| qmail | qmail | 25, 587 | Banner pattern |

**Detection Techniques**:
- SMTP EHLO command
- IMAP CAPABILITY command
- POP3 CAPA command
- Banner string analysis
- Version extraction

### 6. Message Queues (8 services)

Message brokers and queuing systems:

| Service | Product | Default Ports | Detection Method |
|---------|---------|---------------|------------------|
| RabbitMQ | RabbitMQ | 5672, 15672 | AMQP handshake |
| Kafka | Apache Kafka | 9092 | Kafka protocol |
| ActiveMQ | Apache ActiveMQ | 61616, 8161 | HTTP admin interface |
| ZeroMQ | ZeroMQ | Various | ZMTP protocol |
| NATS | NATS | 4222, 6222, 8222 | INFO message |
| Pulsar | Apache Pulsar | 6650, 8080 | Pulsar protocol |
| MQTT | MQTT Broker | 1883, 8883 | MQTT CONNECT |
| Redis Pub/Sub | Redis | 6379 | Redis protocol |

**Detection Techniques**:
- AMQP protocol handshake
- Kafka protocol detection
- MQTT CONNECT packet
- NATS INFO response
- Protocol-specific headers

### 7. Proxies & Load Balancers (6 services)

Reverse proxies and load balancing services:

| Service | Product | Default Ports | Detection Method |
|---------|---------|---------------|------------------|
| Squid | Squid Proxy | 3128, 8080 | Server header |
| HAProxy | HAProxy | 80, 443, 8080 | Server header |
| Varnish | Varnish Cache | 80, 6081, 6082 | X-Varnish header |
| Traefik | Traefik | 80, 443, 8080 | Server header |
| Envoy | Envoy Proxy | 10000, 15000 | Server header |
| Nginx | Nginx (proxy mode) | 80, 443, 8080 | X-Proxy header |

**Detection Techniques**:
- HTTP headers (Server, Via, X-Varnish)
- HTTP response analysis
- Admin interface detection
- Version extraction

### 8. Directory Services (5 services)

Authentication and directory services:

| Service | Product | Default Ports | Detection Method |
|---------|---------|---------------|------------------|
| LDAP | OpenLDAP | 389, 636 | LDAP bind |
| Active Directory | Microsoft AD | 389, 636, 3268, 3269 | LDAP response |
| Kerberos | Kerberos | 88 | Kerberos protocol |
| NIS | NIS | Various | RPC detection |
| RADIUS | RADIUS | 1812, 1813 | RADIUS packet (UDP) |

**Detection Techniques**:
- LDAP bind request
- Kerberos AS-REQ
- RADIUS Access-Request
- Protocol-specific handshakes

### 9. Monitoring & Management (8 services)

System monitoring and management tools:

| Service | Product | Default Ports | Detection Method |
|---------|---------|---------------|------------------|
| Nagios | Nagios | Various | Web interface |
| Zabbix | Zabbix | 10050, 10051 | ZBXD protocol |
| Prometheus | Prometheus | 9090 | HTTP API |
| Grafana | Grafana | 3000 | HTTP interface |
| SNMP | SNMP Agent | 161 | SNMP GetRequest (UDP) |
| Netdata | Netdata | 19999 | HTTP interface |
| Datadog | Datadog Agent | 8125, 8126 | HTTP interface |
| New Relic | New Relic | Various | HTTP interface |

**Detection Techniques**:
- SNMP GET requests
- Zabbix protocol
- HTTP API detection
- Web interface patterns

### 10. Other Services (12+ services)

Additional services and protocols:

| Service | Product | Default Ports | Detection Method |
|---------|---------|---------------|------------------|
| Docker | Docker API | 2375, 2376 | HTTP API |
| Kubernetes | Kubernetes API | 6443, 8443, 443 | HTTP API |
| Git | Git Protocol | 9418 | Git protocol |
| SVN | Subversion | 3690 | SVN protocol |
| Jenkins | Jenkins CI | 8080, 8081 | X-Jenkins header |
| GitLab | GitLab | 80, 443 | HTTP interface |
| Consul | HashiCorp Consul | 8500, 8600 | HTTP API |
| Etcd | etcd | 2379, 2380 | HTTP API |
| DNS | DNS Server | 53 | DNS query (UDP) |
| Minecraft | Minecraft Server | 25565 | Server list ping |
| OpenVPN | OpenVPN | 1194 | OpenVPN protocol (UDP) |
| Rsync | rsync | 873 | rsync protocol |
| Mumble | Mumble VoIP | 64738 | Mumble protocol |
| Kibana | Kibana | 5601 | HTTP API |
| Logstash | Logstash | 9600 | HTTP API |
| SonarQube | SonarQube | 9000 | HTTP interface |
| Splunk | Splunk | 8000, 8089 | HTTP interface |

**Detection Techniques**:
- HTTP REST API detection
- Protocol-specific handshakes
- Banner pattern matching
- JSON API responses

## Probe Database

### Probe Categories

#### 1. Basic Probes
- **NULL**: Simple connection without data
- Used for services that send banners on connect (SSH, FTP, SMTP)

#### 2. HTTP Probes
- **GetRequest**: `GET / HTTP/1.0\r\n\r\n`
- **HTTPOptions**: `OPTIONS / HTTP/1.0\r\n\r\n`
- Used for web servers and HTTP-based services

#### 3. Mail Protocol Probes
- **SMTP**: `EHLO nmap.scanme.org\r\n`
- **POP3**: `CAPA\r\n`
- **IMAP**: `A001 CAPABILITY\r\n`

#### 4. Database Probes
- **MySQL**: Empty (server sends handshake)
- **PostgreSQL**: Startup message packet
- **Redis**: `INFO\r\n`
- **Memcached**: `version\r\n`
- **MongoDB**: Wire protocol query
- **Cassandra**: CQL protocol handshake
- **MSSQL**: TDS protocol handshake
- **Oracle**: TNS protocol handshake

#### 5. File Server Probes
- **FTP**: `HELP\r\n`
- **SMB**: SMB negotiation packet
- **NFS**: RPC NULL call
- **AFP**: AFP protocol handshake
- **TFTP**: Read request (UDP)

#### 6. Remote Access Probes
- **SSH**: `SSH-2.0-Nmap-SSH1-Hostkey\r\n`
- **Telnet**: Telnet option negotiation
- **RDP**: RDP connection request
- **X11**: X11 protocol handshake

#### 7. Directory Service Probes
- **LDAP**: LDAP bind request
- **Kerberos**: Kerberos handshake
- **RADIUS**: RADIUS Access-Request (UDP)

#### 8. Network Management Probes
- **DNSVersionBindReq**: DNS TXT query for version.bind (UDP)
- **SNMPv1GetRequest**: SNMP v1 GET request (UDP)
- **SNMPv3GetRequest**: SNMP v3 GET request (UDP)

#### 9. Message Queue Probes
- **AMQP**: `AMQP\x00\x00\x09\x01`
- **MQTT**: MQTT CONNECT packet
- **NATS**: Empty (server sends INFO)
- **Kafka**: Kafka protocol query
- **ZeroMQ**: ZMTP handshake

#### 10. Monitoring Probes
- **Zabbix**: `ZBXD\x01`

#### 11. Version Control Probes
- **Git**: `git-upload-pack /\0host=nmap\0`
- **SVN**: SVN protocol handshake

### Probe Rarity Levels

Probes are assigned rarity levels (1-9) to control scanning intensity:

- **Rarity 1**: NULL probe (always used)
- **Rarity 2-3**: Common protocols (HTTP, SSH, FTP, SMTP)
- **Rarity 4-5**: Less common protocols (IMAP, POP3, databases)
- **Rarity 6-7**: Uncommon protocols (LDAP, Kerberos, specialized services)
- **Rarity 8-9**: Rare protocols (specialized applications)

## Version Detection

### Version Extraction Patterns

Version information is extracted using regex patterns:

1. **Capture Groups**: Use `$1`, `$2`, etc. for version extraction
2. **Product Name**: Extracted from banners
3. **Version Number**: Parsed from responses
4. **OS Information**: Detected from banner details
5. **CPE Identifiers**: Generated for vulnerability scanning

### Example Patterns

```regex
# Apache HTTP Server
Server: Apache/([0-9.]+)(?:\s+\(([^)]+)\))?
  -> Product: Apache httpd
  -> Version: $1
  -> OS Info: $2

# OpenSSH
SSH-2\.0-OpenSSH_([0-9.]+[p0-9]*)(?:\s+(.+))?
  -> Product: OpenSSH
  -> Version: $1
  -> Info: $2

# MySQL
([0-9.]+)-MariaDB|([0-9.]+).*MySQL
  -> Product: MySQL/MariaDB
  -> Version: $1 or $2
```

## Service Detection Workflow

1. **Port Connection**: Establish TCP/UDP connection
2. **Banner Grabbing**: Wait for server to send banner (NULL probe)
3. **Probe Sending**: Send protocol-specific probes
4. **Response Matching**: Match response against signature database
5. **Version Extraction**: Parse version information from response
6. **CPE Generation**: Generate Common Platform Enumeration identifier

## Performance Optimization

### Lazy Pattern Compilation
- Regex patterns compiled on-demand
- Cached for repeated use
- Indexed by port, service, and probe

### Parallel Detection
- Multiple ports scanned concurrently
- Configurable parallelism level
- Timeout management per connection

### Early Termination
- Stop on first successful match
- Fallback to next probe on timeout
- Skip incompatible probes

## Configuration Options

```rust
pub struct ServiceDetectionOptions {
    pub timeout: Duration,           // Connection timeout
    pub version_intensity: u8,       // Probe intensity (0-9)
    pub enable_banner_grab: bool,    // Enable banner grabbing
    pub max_probes: usize,          // Maximum probes per port
    pub parallel_limit: usize,      // Concurrent connections
}
```

## Usage Example

```rust
use nmap_service_detect::{ServiceDetector, ServiceDetectionOptions};
use std::net::IpAddr;

// Create detector with default database
let detector = ServiceDetector::new()?;

// Configure options
let options = ServiceDetectionOptions {
    timeout: Duration::from_secs(5),
    version_intensity: 7,
    enable_banner_grab: true,
    max_probes: 10,
    parallel_limit: 20,
};

let detector = detector.with_options(options);

// Detect service on a port
let result = detector.detect_service(&host, 80, "tcp").await?;

println!("Service: {}", result.service.name);
println!("Product: {:?}", result.service.product);
println!("Version: {:?}", result.service.version);
println!("CPE: {:?}", result.service.cpe);
```

## Testing

The database includes comprehensive tests:

- **Signature Database Tests**: Verify all signatures load correctly
- **Pattern Matching Tests**: Test regex patterns against sample banners
- **Version Extraction Tests**: Verify version parsing accuracy
- **Protocol-Specific Tests**: Test each major protocol category

Run tests with:
```bash
cargo test -p nmap-service-detect
```

## Future Enhancements

Planned additions to the service database:

1. **SSL/TLS Detection**: Enhanced HTTPS service detection
2. **Custom Signatures**: User-defined signature loading
3. **Machine Learning**: AI-based service classification
4. **Protocol Fingerprinting**: Advanced protocol detection
5. **Performance Metrics**: Success rate tracking
6. **Signature Updates**: Dynamic signature database updates

## Contributing

To add new service signatures:

1. Add signature to `signatures.rs` in the appropriate category
2. Add probe to `probes.rs` if needed
3. Add tests for the new signature
4. Update this documentation
5. Ensure CPE identifiers are correct

## References

- Nmap Service Probes Database
- Common Platform Enumeration (CPE)
- IANA Service Name and Port Number Registry
- Protocol RFCs and specifications

## License

Part of the R-Map project. See main project LICENSE file.
