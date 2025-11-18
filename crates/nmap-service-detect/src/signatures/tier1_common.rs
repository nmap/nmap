use crate::signatures::{ServiceSignature, VersionInfo};

/// Tier 1 Common Services - Most frequently encountered services
/// These signatures are checked first for optimal performance
pub fn load_tier1_signatures() -> Vec<ServiceSignature> {
    let mut signatures = Vec::new();

    // ========== GENERIC HTTP ==========

    // Generic HTTP
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"HTTP/1\.[01] \d+ ".to_string(),
        version_info: Some(VersionInfo {
            product: Some("HTTP server".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:http:http_server".to_string()],
        }),
        ports: vec![80, 8080, 8000, 8008, 8888, 9000],
        protocol: "tcp".to_string(),
    });

    // ========== SSH ==========
    // IMPORTANT: Specific signatures before generic ones!

    // OpenSSH
    signatures.push(ServiceSignature {
        service_name: "ssh".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"SSH-2\.0-OpenSSH_([0-9.]+[p0-9]*)(?:\s+(.+))?".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OpenSSH".to_string()),
            version: Some("$1".to_string()),
            info: Some("$2".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:openbsd:openssh:$1".to_string()],
        }),
        ports: vec![22],
        protocol: "tcp".to_string(),
    });

    // Dropbear SSH
    signatures.push(ServiceSignature {
        service_name: "ssh".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"SSH-2\.0-dropbear_([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Dropbear sshd".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: Some("embedded".to_string()),
            cpe: vec!["cpe:/a:matt_johnston:dropbear_ssh_server:$1".to_string()],
        }),
        ports: vec![22],
        protocol: "tcp".to_string(),
    });

    // Generic SSH (fallback - must be last)
    signatures.push(ServiceSignature {
        service_name: "ssh".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"SSH-([0-9.]+)-(.+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("$2".to_string()),
            version: Some("protocol $1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ssh:ssh:$1".to_string()],
        }),
        ports: vec![22],
        protocol: "tcp".to_string(),
    });

    // ========== FTP ==========
    // IMPORTANT: Specific signatures before generic ones!

    // vsftpd
    signatures.push(ServiceSignature {
        service_name: "ftp".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"220.*vsftpd ([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("vsftpd".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:vsftpd:vsftpd:$1".to_string()],
        }),
        ports: vec![21],
        protocol: "tcp".to_string(),
    });

    // ProFTPD
    signatures.push(ServiceSignature {
        service_name: "ftp".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"220.*ProFTPD ([0-9.]+[a-z]*)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ProFTPD".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:proftpd:proftpd:$1".to_string()],
        }),
        ports: vec![21],
        protocol: "tcp".to_string(),
    });

    // Pure-FTPd
    signatures.push(ServiceSignature {
        service_name: "ftp".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"220.*Pure-FTPd".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Pure-FTPd".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:pureftpd:pure-ftpd".to_string()],
        }),
        ports: vec![21],
        protocol: "tcp".to_string(),
    });

    // FileZilla FTP
    signatures.push(ServiceSignature {
        service_name: "ftp".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"220.*FileZilla Server ([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("FileZilla ftpd".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:filezilla:ftp_server:$1".to_string()],
        }),
        ports: vec![21],
        protocol: "tcp".to_string(),
    });

    // Generic FTP (fallback - must be last)
    signatures.push(ServiceSignature {
        service_name: "ftp".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"220.*FTP".to_string(),
        version_info: Some(VersionInfo {
            product: Some("FTP server".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ftp:ftp_server".to_string()],
        }),
        ports: vec![21],
        protocol: "tcp".to_string(),
    });

    // ========== REMOTE ACCESS ==========

    // Telnet
    signatures.push(ServiceSignature {
        service_name: "telnet".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r".*(?:login|Username|password).*:".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Telnet server".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:telnet:telnet_server".to_string()],
        }),
        ports: vec![23],
        protocol: "tcp".to_string(),
    });

    // Microsoft RDP
    signatures.push(ServiceSignature {
        service_name: "rdp".to_string(),
        probe_name: "RDP".to_string(),
        pattern: r".*RDP.*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Microsoft Terminal Services".to_string()),
            version: None,
            info: Some("RDP".to_string()),
            hostname: None,
            os_type: Some("Windows".to_string()),
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:terminal_services".to_string()],
        }),
        ports: vec![3389],
        protocol: "tcp".to_string(),
    });

    // VNC
    signatures.push(ServiceSignature {
        service_name: "vnc".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"RFB ([0-9]{3}\.[0-9]{3})".to_string(),
        version_info: Some(VersionInfo {
            product: Some("VNC".to_string()),
            version: Some("protocol $1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:realvnc:vnc:$1".to_string()],
        }),
        ports: vec![5900, 5901, 5902],
        protocol: "tcp".to_string(),
    });

    // RealVNC
    signatures.push(ServiceSignature {
        service_name: "vnc".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"RFB.*RealVNC".to_string(),
        version_info: Some(VersionInfo {
            product: Some("RealVNC".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:realvnc:vnc".to_string()],
        }),
        ports: vec![5900],
        protocol: "tcp".to_string(),
    });

    // TightVNC
    signatures.push(ServiceSignature {
        service_name: "vnc".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"RFB.*TightVNC".to_string(),
        version_info: Some(VersionInfo {
            product: Some("TightVNC".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:tightvnc:tightvnc".to_string()],
        }),
        ports: vec![5900],
        protocol: "tcp".to_string(),
    });

    // ========== MAIL ==========

    // Generic SMTP
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"220.*SMTP|220.*ESMTP".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SMTP server".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:smtp:smtp_server".to_string()],
        }),
        ports: vec![25, 587, 465],
        protocol: "tcp".to_string(),
    });

    // POP3
    signatures.push(ServiceSignature {
        service_name: "pop3".to_string(),
        probe_name: "POP3".to_string(),
        pattern: r"\+OK.*POP3".to_string(),
        version_info: Some(VersionInfo {
            product: Some("POP3 server".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:pop3:pop3_server".to_string()],
        }),
        ports: vec![110, 995],
        protocol: "tcp".to_string(),
    });

    // IMAP
    signatures.push(ServiceSignature {
        service_name: "imap".to_string(),
        probe_name: "IMAP".to_string(),
        pattern: r"\* OK.*IMAP".to_string(),
        version_info: Some(VersionInfo {
            product: Some("IMAP server".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:imap:imap_server".to_string()],
        }),
        ports: vec![143, 993],
        protocol: "tcp".to_string(),
    });

    // ========== FILE SERVERS ==========

    // Samba/SMB
    signatures.push(ServiceSignature {
        service_name: "smb".to_string(),
        probe_name: "SMB".to_string(),
        pattern: r"Samba ([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Samba smbd".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:samba:samba:$1".to_string()],
        }),
        ports: vec![139, 445],
        protocol: "tcp".to_string(),
    });

    // Microsoft Windows SMB
    signatures.push(ServiceSignature {
        service_name: "smb".to_string(),
        probe_name: "SMB".to_string(),
        pattern: r"Windows.*SMB".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Microsoft Windows SMB".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: Some("Windows".to_string()),
            device_type: None,
            cpe: vec!["cpe:/o:microsoft:windows".to_string()],
        }),
        ports: vec![139, 445],
        protocol: "tcp".to_string(),
    });

    // TFTP
    signatures.push(ServiceSignature {
        service_name: "tftp".to_string(),
        probe_name: "TFTP".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("TFTP server".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:tftp:tftp_server".to_string()],
        }),
        ports: vec![69],
        protocol: "udp".to_string(),
    });

    // NFS
    signatures.push(ServiceSignature {
        service_name: "nfs".to_string(),
        probe_name: "NFS".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("NFS".to_string()),
            version: None,
            info: Some("Network File System".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nfs:nfs".to_string()],
        }),
        ports: vec![2049],
        protocol: "tcp".to_string(),
    });

    // AFP (Apple Filing Protocol)
    signatures.push(ServiceSignature {
        service_name: "afp".to_string(),
        probe_name: "AFP".to_string(),
        pattern: r"AFP.*([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apple Filing Protocol".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: Some("Mac OS X".to_string()),
            device_type: None,
            cpe: vec!["cpe:/a:apple:afp:$1".to_string()],
        }),
        ports: vec![548],
        protocol: "tcp".to_string(),
    });

    // ========== NETWORK SERVICES ==========

    // DNS
    signatures.push(ServiceSignature {
        service_name: "dns".to_string(),
        probe_name: "DNSVersionBindReq".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("DNS server".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:dns:dns_server".to_string()],
        }),
        ports: vec![53],
        protocol: "udp".to_string(),
    });

    // SNMP
    signatures.push(ServiceSignature {
        service_name: "snmp".to_string(),
        probe_name: "SNMPv1GetRequest".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SNMP".to_string()),
            version: None,
            info: Some("Simple Network Management Protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:snmp:snmp".to_string()],
        }),
        ports: vec![161],
        protocol: "udp".to_string(),
    });

    // ========== OTHER COMMON SERVICES ==========

    // X11
    signatures.push(ServiceSignature {
        service_name: "x11".to_string(),
        probe_name: "X11".to_string(),
        pattern: r"^[BNl].*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("X11 server".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:x:x11".to_string()],
        }),
        ports: vec![6000, 6001, 6002],
        protocol: "tcp".to_string(),
    });

    // TeamViewer
    signatures.push(ServiceSignature {
        service_name: "teamviewer".to_string(),
        probe_name: "TeamViewer".to_string(),
        pattern: r"TeamViewer".to_string(),
        version_info: Some(VersionInfo {
            product: Some("TeamViewer".to_string()),
            version: None,
            info: Some("Remote desktop software".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:teamviewer:teamviewer".to_string()],
        }),
        ports: vec![5938],
        protocol: "tcp".to_string(),
    });

    // Rsync
    signatures.push(ServiceSignature {
        service_name: "rsync".to_string(),
        probe_name: "Rsync".to_string(),
        pattern: r"@RSYNCD:".to_string(),
        version_info: Some(VersionInfo {
            product: Some("rsync".to_string()),
            version: None,
            info: Some("File synchronization".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:rsync:rsync".to_string()],
        }),
        ports: vec![873],
        protocol: "tcp".to_string(),
    });

    // Minecraft Server
    signatures.push(ServiceSignature {
        service_name: "minecraft".to_string(),
        probe_name: "Minecraft".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Minecraft Server".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mojang:minecraft_server".to_string()],
        }),
        ports: vec![25565],
        protocol: "tcp".to_string(),
    });

    // OpenVPN
    signatures.push(ServiceSignature {
        service_name: "openvpn".to_string(),
        probe_name: "OpenVPN".to_string(),
        pattern: r"OpenVPN".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OpenVPN".to_string()),
            version: None,
            info: Some("VPN service".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:openvpn:openvpn".to_string()],
        }),
        ports: vec![1194],
        protocol: "udp".to_string(),
    });

    // Mumble (VoIP)
    signatures.push(ServiceSignature {
        service_name: "mumble".to_string(),
        probe_name: "Mumble".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Mumble VoIP".to_string()),
            version: None,
            info: Some("Voice chat server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mumble:mumble".to_string()],
        }),
        ports: vec![64738],
        protocol: "tcp".to_string(),
    });

    signatures
}
