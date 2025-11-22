use serde_json::{json, Value};

/// Get all MCP tool definitions
pub fn get_tool_definitions() -> Vec<Value> {
    vec![
        define_rmap_scan(),
        define_rmap_service_detect(),
        define_rmap_os_detect(),
        define_rmap_comprehensive_scan(),
        define_rmap_export(),
        define_rmap_history(),
    ]
}

fn define_rmap_scan() -> Value {
    json!({
        "name": "rmap_scan",
        "description": "Perform network port scanning with R-Map.\n\nSupports multiple scan types:\n- TCP SYN scan (stealth, requires root)\n- TCP Connect scan (no root required)\n- UDP scan\n- Advanced TCP scans (ACK, FIN, NULL, Xmas)\n\nPerformance: 10,000-15,000 ports/sec throughput.\n\nParameters:\n- target: IP address, hostname, or CIDR range (e.g., \"192.168.1.1\", \"example.com\", \"10.0.0.0/24\")\n- ports: Port specification (e.g., \"80,443\", \"1-1000\", \"top-100\", \"all\")\n- scan_type: Scan type - \"syn\" (default), \"connect\", \"udp\", \"ack\", \"fin\", \"null\", \"xmas\"\n- timing: Timing template - \"paranoid\", \"sneaky\", \"polite\", \"normal\" (default), \"aggressive\", \"insane\"\n- output_format: Output format - \"normal\", \"json\" (default), \"xml\", \"grepable\"\n- skip_ping: Skip host discovery (default: false)\n- max_rate: Maximum packets per second (default: none)\n- timeout: Scan timeout in seconds (default: 300)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP, hostname, or CIDR range"
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification",
                    "default": "top-100"
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["syn", "connect", "udp", "ack", "fin", "null", "xmas"],
                    "description": "Scan type",
                    "default": "syn"
                },
                "timing": {
                    "type": "string",
                    "enum": ["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
                    "description": "Timing template",
                    "default": "normal"
                },
                "output_format": {
                    "type": "string",
                    "enum": ["normal", "json", "xml", "grepable"],
                    "description": "Output format",
                    "default": "json"
                },
                "skip_ping": {
                    "type": "boolean",
                    "description": "Skip host discovery",
                    "default": false
                },
                "max_rate": {
                    "type": "integer",
                    "description": "Maximum packets per second",
                    "minimum": 1,
                    "maximum": 100000
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan timeout in seconds",
                    "default": 300,
                    "minimum": 10,
                    "maximum": 3600
                }
            },
            "required": ["target"]
        }
    })
}

fn define_rmap_service_detect() -> Value {
    json!({
        "name": "rmap_service_detect",
        "description": "Detect services and versions running on open ports.\n\nR-Map includes 411+ service signatures across multiple tiers:\n- Tier 1: Common services (HTTP, HTTPS, SSH, FTP, SMTP, etc.)\n- Tier 2: Databases, mail servers, web servers, message queues, monitoring\n- Tier 3: Cloud services, IoT protocols, VPN, specialized services\n\nCapabilities:\n- Banner grabbing and analysis\n- SSL/TLS certificate inspection\n- Application fingerprinting\n- Version detection\n\nParameters:\n- target: IP address or hostname\n- ports: Port specification (default: scan all ports first)\n- intensity: Detection intensity 0-9 (default: 7)\n- timeout: Service detection timeout in seconds (default: 300)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP or hostname"
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification",
                    "default": "top-100"
                },
                "intensity": {
                    "type": "integer",
                    "description": "Detection intensity (0-9)",
                    "minimum": 0,
                    "maximum": 9,
                    "default": 7
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 300,
                    "minimum": 10,
                    "maximum": 3600
                }
            },
            "required": ["target"]
        }
    })
}

fn define_rmap_os_detect() -> Value {
    json!({
        "name": "rmap_os_detect",
        "description": "Perform operating system fingerprinting and detection.\n\nR-Map includes 139+ OS signatures using multiple detection methods:\n- Active OS fingerprinting (TCP/IP stack analysis)\n- Passive OS fingerprinting (traffic analysis)\n- Application-layer detection (service banners)\n- Bayesian fusion for accurate results\n\nSupported OS families:\n- Windows (all versions from XP to 11, Server 2003-2022)\n- Linux (Ubuntu, Debian, CentOS, RHEL, Alpine, etc.)\n- BSD (FreeBSD, OpenBSD, NetBSD)\n- macOS/iOS\n- Network devices (Cisco, Juniper, MikroTik, etc.)\n- Embedded/IoT devices\n\nParameters:\n- target: IP address or hostname\n- method: Detection method - \"active\", \"passive\", \"app-layer\", \"all\" (default: \"all\")\n- intensity: Detection intensity 0-9 (default: 7)\n- timeout: Detection timeout in seconds (default: 300)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP or hostname"
                },
                "method": {
                    "type": "string",
                    "enum": ["active", "passive", "app-layer", "all"],
                    "description": "Detection method",
                    "default": "all"
                },
                "intensity": {
                    "type": "integer",
                    "description": "Detection intensity (0-9)",
                    "minimum": 0,
                    "maximum": 9,
                    "default": 7
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 300,
                    "minimum": 10,
                    "maximum": 3600
                }
            },
            "required": ["target"]
        }
    })
}

fn define_rmap_comprehensive_scan() -> Value {
    json!({
        "name": "rmap_comprehensive_scan",
        "description": "Perform comprehensive network reconnaissance combining all R-Map capabilities.\n\nThis tool combines:\n- Port scanning (TCP/UDP)\n- Service version detection\n- OS fingerprinting\n- Banner grabbing\n- SSL/TLS analysis\n\nOutput includes:\n- All open/filtered ports\n- Detected services and versions\n- Operating system identification\n- Network topology insights\n- Security recommendations\n\nParameters:\n- target: IP address, hostname, or CIDR range\n- scan_profile: Scan profile - \"quick\" (top 100 ports), \"standard\" (top 1000), \"thorough\" (all ports), \"custom\"\n- custom_ports: Custom port specification (only if scan_profile=\"custom\")\n- timing: Timing template (default: \"normal\")\n- output_format: Output format (default: \"json\")\n- timeout: Total scan timeout in seconds (default: 600)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP, hostname, or CIDR range"
                },
                "scan_profile": {
                    "type": "string",
                    "enum": ["quick", "standard", "thorough", "custom"],
                    "description": "Scan profile",
                    "default": "standard"
                },
                "custom_ports": {
                    "type": "string",
                    "description": "Custom port specification (for custom profile)"
                },
                "timing": {
                    "type": "string",
                    "enum": ["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
                    "description": "Timing template",
                    "default": "normal"
                },
                "output_format": {
                    "type": "string",
                    "enum": ["normal", "json", "xml"],
                    "description": "Output format",
                    "default": "json"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Total scan timeout in seconds",
                    "default": 600,
                    "minimum": 60,
                    "maximum": 7200
                }
            },
            "required": ["target"]
        }
    })
}

fn define_rmap_export() -> Value {
    json!({
        "name": "rmap_export",
        "description": "Export R-Map scan results in various formats.\n\nSupported formats:\n- JSON: Machine-readable structured data\n- XML: Compatible with other security tools\n- HTML: Interactive web report with visualizations\n- PDF: Executive summary and technical report (future)\n- Markdown: Documentation-friendly format\n- CSV: Spreadsheet-compatible tabular data (future)\n- SQLite: Database for historical tracking (stored automatically)\n- Grepable: Easy parsing with grep/awk (future)\n\nParameters:\n- scan_id: UUID of the scan to export (from scan result)\n- format: Export format\n- output_file: Output file path (optional, returns content if not specified)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "string",
                    "description": "UUID of scan to export"
                },
                "format": {
                    "type": "string",
                    "enum": ["json", "xml", "html", "markdown"],
                    "description": "Export format"
                },
                "output_file": {
                    "type": "string",
                    "description": "Output file path (optional)"
                }
            },
            "required": ["scan_id", "format"]
        }
    })
}

fn define_rmap_history() -> Value {
    json!({
        "name": "rmap_history",
        "description": "Retrieve scan history from the redb database.\n\nShows recent scans with:\n- Scan ID (UUID)\n- Target\n- Scan type\n- Timestamp\n- Status\n\nUse this to find scan IDs for export or review past reconnaissance activities.\n\nParameters:\n- limit: Number of recent scans to retrieve (default: 10, max: 100)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Number of scans to retrieve",
                    "default": 10,
                    "minimum": 1,
                    "maximum": 100
                }
            }
        }
    })
}
