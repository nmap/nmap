use crate::signatures::{ServiceSignature, VersionInfo};

/// Tier 3 VPN & Secure Tunneling - VPN, secure tunnel, and zero-trust network signatures
/// Covers OpenVPN, WireGuard, IPSec, SSL VPN, and modern zero-trust solutions
pub fn load_tier3_vpn_signatures() -> Vec<ServiceSignature> {
    let mut signatures = Vec::new();

    // ========== OPENVPN ==========

    // OpenVPN TCP
    signatures.push(ServiceSignature {
        service_name: "openvpn-tcp".to_string(),
        probe_name: "OpenVPN".to_string(),
        pattern: r"\x00[\x0e-\x40]".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OpenVPN".to_string()),
            version: None,
            info: Some("VPN service over TCP".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:openvpn:openvpn".to_string()],
        }),
        ports: vec![443, 1194, 943],
        protocol: "tcp".to_string(),
    });

    // OpenVPN UDP
    signatures.push(ServiceSignature {
        service_name: "openvpn-udp".to_string(),
        probe_name: "OpenVPN".to_string(),
        pattern: r"\x00[\x0e-\x40]".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OpenVPN".to_string()),
            version: None,
            info: Some("VPN service over UDP".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:openvpn:openvpn".to_string()],
        }),
        ports: vec![1194],
        protocol: "udp".to_string(),
    });

    // OpenVPN Access Server
    signatures.push(ServiceSignature {
        service_name: "openvpn-as".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"OpenVPN.*Access.*Server".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OpenVPN Access Server".to_string()),
            version: None,
            info: Some("Commercial OpenVPN solution".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:openvpn:openvpn_access_server".to_string()],
        }),
        ports: vec![943, 443],
        protocol: "tcp".to_string(),
    });

    // ========== WIREGUARD ==========

    // WireGuard
    signatures.push(ServiceSignature {
        service_name: "wireguard".to_string(),
        probe_name: "WireGuard".to_string(),
        pattern: r"\x01\x00\x00\x00".to_string(),
        version_info: Some(VersionInfo {
            product: Some("WireGuard".to_string()),
            version: None,
            info: Some("Modern VPN protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:wireguard:wireguard".to_string()],
        }),
        ports: vec![51820],
        protocol: "udp".to_string(),
    });

    // ========== IPSEC ==========

    // IKEv2 (Internet Key Exchange)
    signatures.push(ServiceSignature {
        service_name: "ikev2".to_string(),
        probe_name: "IKEv2".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("IKEv2".to_string()),
            version: None,
            info: Some("IPsec key exchange protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ietf:ikev2".to_string()],
        }),
        ports: vec![500, 4500],
        protocol: "udp".to_string(),
    });

    // IPsec NAT-T
    signatures.push(ServiceSignature {
        service_name: "ipsec-nat-t".to_string(),
        probe_name: "IPsec".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("IPsec NAT-T".to_string()),
            version: None,
            info: Some("IPsec NAT Traversal".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ietf:ipsec".to_string()],
        }),
        ports: vec![4500],
        protocol: "udp".to_string(),
    });

    // strongSwan
    signatures.push(ServiceSignature {
        service_name: "strongswan".to_string(),
        probe_name: "IKE".to_string(),
        pattern: r"strongSwan".to_string(),
        version_info: Some(VersionInfo {
            product: Some("strongSwan".to_string()),
            version: None,
            info: Some("IPsec-based VPN solution".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:strongswan:strongswan".to_string()],
        }),
        ports: vec![500, 4500],
        protocol: "udp".to_string(),
    });

    // ========== SSL VPN ==========

    // Cisco AnyConnect
    signatures.push(ServiceSignature {
        service_name: "cisco-anyconnect".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"webvpn|anyconnect".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Cisco AnyConnect".to_string()),
            version: None,
            info: Some("SSL VPN client".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:cisco:anyconnect_secure_mobility_client".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // Fortinet SSL VPN
    signatures.push(ServiceSignature {
        service_name: "fortinet-sslvpn".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"FortiGate|fortinet".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Fortinet SSL VPN".to_string()),
            version: None,
            info: Some("FortiGate VPN service".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:fortinet:fortigate".to_string()],
        }),
        ports: vec![443, 10443],
        protocol: "tcp".to_string(),
    });

    // Palo Alto GlobalProtect
    signatures.push(ServiceSignature {
        service_name: "globalprotect".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"GlobalProtect".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Palo Alto GlobalProtect".to_string()),
            version: None,
            info: Some("Enterprise VPN solution".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:paloaltonetworks:globalprotect".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // SonicWall SSL VPN
    signatures.push(ServiceSignature {
        service_name: "sonicwall-sslvpn".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"SonicWall|sslvpn".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SonicWall SSL VPN".to_string()),
            version: None,
            info: Some("SonicWall VPN service".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:sonicwall:sslvpn".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // Pulse Secure
    signatures.push(ServiceSignature {
        service_name: "pulse-secure".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Pulse.*Secure|dana-na".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Pulse Secure".to_string()),
            version: None,
            info: Some("SSL VPN solution".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:pulsesecure:pulse_connect_secure".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // Checkpoint SSL VPN
    signatures.push(ServiceSignature {
        service_name: "checkpoint-sslvpn".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Check Point|SNX".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Check Point SSL VPN".to_string()),
            version: None,
            info: Some("Secure Network Extender".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:checkpoint:vpn".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // ========== MODERN VPN SOLUTIONS ==========

    // Tailscale
    signatures.push(ServiceSignature {
        service_name: "tailscale".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Tailscale".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Tailscale".to_string()),
            version: None,
            info: Some("WireGuard-based mesh VPN".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:tailscale:tailscale".to_string()],
        }),
        ports: vec![41641],
        protocol: "udp".to_string(),
    });

    // ZeroTier
    signatures.push(ServiceSignature {
        service_name: "zerotier".to_string(),
        probe_name: "ZeroTier".to_string(),
        pattern: r"zerotier".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ZeroTier".to_string()),
            version: None,
            info: Some("Software-defined networking".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:zerotier:zerotier".to_string()],
        }),
        ports: vec![9993],
        protocol: "udp".to_string(),
    });

    // Netmaker
    signatures.push(ServiceSignature {
        service_name: "netmaker".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Netmaker".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Netmaker".to_string()),
            version: None,
            info: Some("WireGuard automation platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:gravitl:netmaker".to_string()],
        }),
        ports: vec![8081],
        protocol: "tcp".to_string(),
    });

    // Nebula
    signatures.push(ServiceSignature {
        service_name: "nebula".to_string(),
        probe_name: "Nebula".to_string(),
        pattern: r"nebula".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Nebula".to_string()),
            version: None,
            info: Some("Overlay network by Slack".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:slack:nebula".to_string()],
        }),
        ports: vec![4242],
        protocol: "udp".to_string(),
    });

    // ========== SSH-BASED VPN ==========

    // SSH Tunnel
    signatures.push(ServiceSignature {
        service_name: "ssh-tunnel".to_string(),
        probe_name: "SSH".to_string(),
        pattern: r"SSH.*tunnel|ssh.*vpn".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SSH Tunnel".to_string()),
            version: None,
            info: Some("VPN over SSH".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ssh:ssh_tunnel".to_string()],
        }),
        ports: vec![22],
        protocol: "tcp".to_string(),
    });

    // sshuttle
    signatures.push(ServiceSignature {
        service_name: "sshuttle".to_string(),
        probe_name: "SSH".to_string(),
        pattern: r"sshuttle".to_string(),
        version_info: Some(VersionInfo {
            product: Some("sshuttle".to_string()),
            version: None,
            info: Some("Transparent proxy VPN over SSH".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:sshuttle:sshuttle".to_string()],
        }),
        ports: vec![22],
        protocol: "tcp".to_string(),
    });

    // ========== PROXY & SOCKS ==========

    // SOCKS5 Proxy
    signatures.push(ServiceSignature {
        service_name: "socks5".to_string(),
        probe_name: "SOCKS".to_string(),
        pattern: r"\x05".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SOCKS5 Proxy".to_string()),
            version: None,
            info: Some("SOCKS protocol version 5".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:socks:socks5".to_string()],
        }),
        ports: vec![1080, 1081],
        protocol: "tcp".to_string(),
    });

    // Shadowsocks
    signatures.push(ServiceSignature {
        service_name: "shadowsocks".to_string(),
        probe_name: "Shadowsocks".to_string(),
        pattern: r"shadowsocks".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Shadowsocks".to_string()),
            version: None,
            info: Some("Secure SOCKS5 proxy".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:shadowsocks:shadowsocks".to_string()],
        }),
        ports: vec![8388],
        protocol: "tcp".to_string(),
    });

    // V2Ray
    signatures.push(ServiceSignature {
        service_name: "v2ray".to_string(),
        probe_name: "V2Ray".to_string(),
        pattern: r"v2ray|vmess".to_string(),
        version_info: Some(VersionInfo {
            product: Some("V2Ray".to_string()),
            version: None,
            info: Some("Platform for proxying".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:v2ray:v2ray".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // ========== CORPORATE VPN ==========

    // Microsoft DirectAccess
    signatures.push(ServiceSignature {
        service_name: "directaccess".to_string(),
        probe_name: "DirectAccess".to_string(),
        pattern: r"DirectAccess".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Microsoft DirectAccess".to_string()),
            version: None,
            info: Some("Always On VPN".to_string()),
            hostname: None,
            os_type: Some("Windows".to_string()),
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:directaccess".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // Cisco VPN (legacy)
    signatures.push(ServiceSignature {
        service_name: "cisco-vpn".to_string(),
        probe_name: "CiscoVPN".to_string(),
        pattern: r"cisco.*vpn".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Cisco VPN".to_string()),
            version: None,
            info: Some("Legacy Cisco VPN client".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:cisco:vpn_client".to_string()],
        }),
        ports: vec![10000],
        protocol: "udp".to_string(),
    });

    // Juniper SSL VPN
    signatures.push(ServiceSignature {
        service_name: "juniper-sslvpn".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Juniper.*SSL|PULSESECURE".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Juniper SSL VPN".to_string()),
            version: None,
            info: Some("Juniper VPN service".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:juniper:ssl_vpn".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // ========== ZERO TRUST NETWORK ACCESS (ZTNA) ==========

    // Cloudflare Access
    signatures.push(ServiceSignature {
        service_name: "cloudflare-access".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Cloudflare.*Access|CF-Access".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Cloudflare Access".to_string()),
            version: None,
            info: Some("Zero trust network access".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:cloudflare:access".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // Okta Access Gateway
    signatures.push(ServiceSignature {
        service_name: "okta-access-gateway".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Okta.*Access.*Gateway".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Okta Access Gateway".to_string()),
            version: None,
            info: Some("Identity-aware proxy".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:okta:access_gateway".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // Zscaler Private Access
    signatures.push(ServiceSignature {
        service_name: "zscaler-zpa".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Zscaler.*Private.*Access|ZPA".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Zscaler Private Access".to_string()),
            version: None,
            info: Some("Cloud-delivered ZTNA".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:zscaler:private_access".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // Perimeter 81
    signatures.push(ServiceSignature {
        service_name: "perimeter81".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Perimeter.*81".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Perimeter 81".to_string()),
            version: None,
            info: Some("Zero trust secure access".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:perimeter81:perimeter81".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // ========== OPEN SOURCE VPN ==========

    // SoftEther VPN
    signatures.push(ServiceSignature {
        service_name: "softether".to_string(),
        probe_name: "SoftEther".to_string(),
        pattern: r"SoftEther".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SoftEther VPN".to_string()),
            version: None,
            info: Some("Multi-protocol VPN software".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:softether:vpn".to_string()],
        }),
        ports: vec![443, 992, 1194, 5555],
        protocol: "tcp".to_string(),
    });

    // Pritunl
    signatures.push(ServiceSignature {
        service_name: "pritunl".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Pritunl".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Pritunl".to_string()),
            version: None,
            info: Some("OpenVPN management server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:pritunl:pritunl".to_string()],
        }),
        ports: vec![443, 9700],
        protocol: "tcp".to_string(),
    });

    // Algo VPN
    signatures.push(ServiceSignature {
        service_name: "algo-vpn".to_string(),
        probe_name: "IKE".to_string(),
        pattern: r"algo".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Algo VPN".to_string()),
            version: None,
            info: Some("Personal IPsec VPN".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:trailofbits:algo".to_string()],
        }),
        ports: vec![500, 4500],
        protocol: "udp".to_string(),
    });

    // ========== MESH VPN ==========

    // Tinc VPN
    signatures.push(ServiceSignature {
        service_name: "tinc".to_string(),
        probe_name: "Tinc".to_string(),
        pattern: r"tinc".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Tinc VPN".to_string()),
            version: None,
            info: Some("Mesh VPN daemon".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:tinc:tinc".to_string()],
        }),
        ports: vec![655],
        protocol: "tcp".to_string(),
    });

    // Freelan
    signatures.push(ServiceSignature {
        service_name: "freelan".to_string(),
        probe_name: "Freelan".to_string(),
        pattern: r"freelan".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Freelan".to_string()),
            version: None,
            info: Some("P2P mesh VPN".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:freelan:freelan".to_string()],
        }),
        ports: vec![12000],
        protocol: "udp".to_string(),
    });

    // ========== ADVANCED TUNNELING ==========

    // Stunnel
    signatures.push(ServiceSignature {
        service_name: "stunnel".to_string(),
        probe_name: "SSL".to_string(),
        pattern: r"stunnel".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Stunnel".to_string()),
            version: None,
            info: Some("SSL encryption wrapper".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:stunnel:stunnel".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // n2n (peer-to-peer VPN)
    signatures.push(ServiceSignature {
        service_name: "n2n".to_string(),
        probe_name: "N2N".to_string(),
        pattern: r"n2n".to_string(),
        version_info: Some(VersionInfo {
            product: Some("n2n".to_string()),
            version: None,
            info: Some("Layer 2 P2P VPN".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ntop:n2n".to_string()],
        }),
        ports: vec![7654],
        protocol: "udp".to_string(),
    });

    // OpenConnect
    signatures.push(ServiceSignature {
        service_name: "openconnect".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"openconnect".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OpenConnect".to_string()),
            version: None,
            info: Some("SSL VPN client/server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:infradead:openconnect".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // ocserv (OpenConnect Server)
    signatures.push(ServiceSignature {
        service_name: "ocserv".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"ocserv".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ocserv".to_string()),
            version: None,
            info: Some("OpenConnect VPN server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:infradead:ocserv".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // L2TP
    signatures.push(ServiceSignature {
        service_name: "l2tp".to_string(),
        probe_name: "L2TP".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("L2TP".to_string()),
            version: None,
            info: Some("Layer 2 Tunneling Protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ietf:l2tp".to_string()],
        }),
        ports: vec![1701],
        protocol: "udp".to_string(),
    });

    // PPTP
    signatures.push(ServiceSignature {
        service_name: "pptp".to_string(),
        probe_name: "PPTP".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("PPTP".to_string()),
            version: None,
            info: Some("Point-to-Point Tunneling Protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:pptp".to_string()],
        }),
        ports: vec![1723],
        protocol: "tcp".to_string(),
    });

    // SSTP (Secure Socket Tunneling Protocol)
    signatures.push(ServiceSignature {
        service_name: "sstp".to_string(),
        probe_name: "SSTP".to_string(),
        pattern: r"SSTP".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SSTP".to_string()),
            version: None,
            info: Some("Microsoft VPN protocol".to_string()),
            hostname: None,
            os_type: Some("Windows".to_string()),
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:sstp".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    signatures
}
