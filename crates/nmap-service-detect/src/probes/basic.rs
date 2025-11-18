use crate::probes::Probe;

/// Load basic protocol probes - HTTP, FTP, SSH, SMTP, etc.
/// These are the most common probes used for service detection
pub fn load_basic_probes() -> Vec<Probe> {
    let mut probes = Vec::new();

    // NULL probe - just connect
    probes.push(Probe {
        name: "NULL".to_string(),
        protocol: "tcp".to_string(),
        data: vec![],
        ports: (1..=65535).collect(),
        ssl_ports: vec![443, 993, 995, 8443],
        rarity: 1,
        fallback: None,
    });

    // ========== HTTP PROBES ==========

    // HTTP GET probe
    probes.push(Probe {
        name: "GetRequest".to_string(),
        protocol: "tcp".to_string(),
        data: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
        ports: vec![80, 8080, 8000, 8008, 8888, 9000, 3000, 5000],
        ssl_ports: vec![443, 8443],
        rarity: 2,
        fallback: Some("NULL".to_string()),
    });

    // HTTP OPTIONS probe
    probes.push(Probe {
        name: "HTTPOptions".to_string(),
        protocol: "tcp".to_string(),
        data: b"OPTIONS / HTTP/1.0\r\n\r\n".to_vec(),
        ports: vec![80, 8080, 443],
        ssl_ports: vec![443],
        rarity: 3,
        fallback: Some("GetRequest".to_string()),
    });

    // ========== FTP PROBES ==========

    // FTP probe
    probes.push(Probe {
        name: "FTP".to_string(),
        protocol: "tcp".to_string(),
        data: b"HELP\r\n".to_vec(),
        ports: vec![21],
        ssl_ports: vec![990],
        rarity: 3,
        fallback: Some("NULL".to_string()),
    });

    // ========== SSH PROBES ==========

    // SSH probe
    probes.push(Probe {
        name: "SSH".to_string(),
        protocol: "tcp".to_string(),
        data: b"SSH-2.0-Nmap-SSH1-Hostkey\r\n".to_vec(),
        ports: vec![22],
        ssl_ports: vec![],
        rarity: 3,
        fallback: Some("NULL".to_string()),
    });

    // ========== MAIL SERVER PROBES ==========

    // SMTP probe
    probes.push(Probe {
        name: "SMTP".to_string(),
        protocol: "tcp".to_string(),
        data: b"EHLO nmap.scanme.org\r\n".to_vec(),
        ports: vec![25, 587],
        ssl_ports: vec![465],
        rarity: 3,
        fallback: Some("NULL".to_string()),
    });

    // POP3 probe
    probes.push(Probe {
        name: "POP3".to_string(),
        protocol: "tcp".to_string(),
        data: b"CAPA\r\n".to_vec(),
        ports: vec![110],
        ssl_ports: vec![995],
        rarity: 4,
        fallback: Some("NULL".to_string()),
    });

    // IMAP probe
    probes.push(Probe {
        name: "IMAP".to_string(),
        protocol: "tcp".to_string(),
        data: b"A001 CAPABILITY\r\n".to_vec(),
        ports: vec![143],
        ssl_ports: vec![993],
        rarity: 4,
        fallback: Some("NULL".to_string()),
    });

    // ========== FILE SERVER PROBES ==========

    // SMB probe
    probes.push(Probe {
        name: "SMB".to_string(),
        protocol: "tcp".to_string(),
        data: vec![
            0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42,
            0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
        ],
        ports: vec![139, 445],
        ssl_ports: vec![],
        rarity: 5,
        fallback: Some("NULL".to_string()),
    });

    // NFS probe (RPC NULL)
    probes.push(Probe {
        name: "NFS".to_string(),
        protocol: "tcp".to_string(),
        data: vec![
            0x80, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ],
        ports: vec![2049],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // AFP probe (Apple Filing Protocol)
    probes.push(Probe {
        name: "AFP".to_string(),
        protocol: "tcp".to_string(),
        data: vec![
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ],
        ports: vec![548],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // TFTP probe
    probes.push(Probe {
        name: "TFTP".to_string(),
        protocol: "udp".to_string(),
        data: vec![
            0x00, 0x01, 0x6e, 0x65, 0x74, 0x61, 0x73, 0x63,
            0x69, 0x69, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00,
        ],
        ports: vec![69],
        ssl_ports: vec![],
        rarity: 6,
        fallback: None,
    });

    // ========== REMOTE ACCESS PROBES ==========

    // Telnet probe
    probes.push(Probe {
        name: "Telnet".to_string(),
        protocol: "tcp".to_string(),
        data: vec![0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03, 0xff, 0xfc, 0x22],
        ports: vec![23],
        ssl_ports: vec![],
        rarity: 4,
        fallback: Some("NULL".to_string()),
    });

    // RDP probe
    probes.push(Probe {
        name: "RDP".to_string(),
        protocol: "tcp".to_string(),
        data: vec![
            0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ],
        ports: vec![3389],
        ssl_ports: vec![],
        rarity: 5,
        fallback: Some("NULL".to_string()),
    });

    // X11 probe
    probes.push(Probe {
        name: "X11".to_string(),
        protocol: "tcp".to_string(),
        data: vec![
            0x6c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        ports: vec![6000, 6001, 6002],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // TeamViewer probe
    probes.push(Probe {
        name: "TeamViewer".to_string(),
        protocol: "tcp".to_string(),
        data: vec![0x17, 0x24, 0x00, 0x01],
        ports: vec![5938],
        ssl_ports: vec![],
        rarity: 7,
        fallback: Some("NULL".to_string()),
    });

    // ========== DIRECTORY SERVICE PROBES ==========

    // LDAP probe
    probes.push(Probe {
        name: "LDAP".to_string(),
        protocol: "tcp".to_string(),
        data: vec![
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02,
            0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ],
        ports: vec![389, 636, 3268, 3269],
        ssl_ports: vec![636, 3269],
        rarity: 5,
        fallback: Some("NULL".to_string()),
    });

    // Kerberos probe
    probes.push(Probe {
        name: "Kerberos".to_string(),
        protocol: "tcp".to_string(),
        data: vec![
            0x00, 0x00, 0x00, 0x00,
        ],
        ports: vec![88],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // NIS probe
    probes.push(Probe {
        name: "NIS".to_string(),
        protocol: "tcp".to_string(),
        data: vec![],
        ports: vec![],
        ssl_ports: vec![],
        rarity: 7,
        fallback: Some("NULL".to_string()),
    });

    // RADIUS probe
    probes.push(Probe {
        name: "RADIUS".to_string(),
        protocol: "udp".to_string(),
        data: vec![
            0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        ports: vec![1812, 1813],
        ssl_ports: vec![],
        rarity: 6,
        fallback: None,
    });

    // ========== NETWORK MANAGEMENT PROBES ==========

    // DNS probe
    probes.push(Probe {
        name: "DNSVersionBindReq".to_string(),
        protocol: "udp".to_string(),
        data: vec![
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x07, 0x76, 0x65, 0x72,
            0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e,
            0x64, 0x00, 0x00, 0x10, 0x00, 0x03,
        ],
        ports: vec![53],
        ssl_ports: vec![],
        rarity: 4,
        fallback: None,
    });

    // SNMP v1 probe
    probes.push(Probe {
        name: "SNMPv1GetRequest".to_string(),
        protocol: "udp".to_string(),
        data: vec![
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
            0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
            0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00,
            0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
            0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
        ],
        ports: vec![161],
        ssl_ports: vec![],
        rarity: 5,
        fallback: None,
    });

    // SNMP v3 probe
    probes.push(Probe {
        name: "SNMPv3GetRequest".to_string(),
        protocol: "udp".to_string(),
        data: vec![
            0x30, 0x3a, 0x02, 0x01, 0x03, 0x30, 0x0f, 0x02,
            0x02, 0x4a, 0x69, 0x02, 0x03, 0x00, 0xff, 0xe3,
            0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10,
            0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02,
            0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00,
            0x30, 0x12, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0c,
            0x02, 0x02, 0x37, 0xf0, 0x02, 0x01, 0x00, 0x02,
            0x01, 0x00, 0x30, 0x00,
        ],
        ports: vec![161],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("SNMPv1GetRequest".to_string()),
    });

    // ========== VERSION CONTROL PROBES ==========

    // Git protocol probe
    probes.push(Probe {
        name: "Git".to_string(),
        protocol: "tcp".to_string(),
        data: b"git-upload-pack /\0host=nmap\0".to_vec(),
        ports: vec![9418],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // SVN probe
    probes.push(Probe {
        name: "SVN".to_string(),
        protocol: "tcp".to_string(),
        data: b"( 2 ( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay inherited-props ephemeral-txnprops file-revs-reverse list ) 36:svn://host/svn/test-repository ) ".to_vec(),
        ports: vec![3690],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // ========== OTHER PROBES ==========

    // Zabbix probe
    probes.push(Probe {
        name: "Zabbix".to_string(),
        protocol: "tcp".to_string(),
        data: b"ZBXD\x01".to_vec(),
        ports: vec![10050, 10051],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // Rsync probe
    probes.push(Probe {
        name: "Rsync".to_string(),
        protocol: "tcp".to_string(),
        data: vec![],
        ports: vec![873],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // Minecraft probe
    probes.push(Probe {
        name: "Minecraft".to_string(),
        protocol: "tcp".to_string(),
        data: vec![],
        ports: vec![25565],
        ssl_ports: vec![],
        rarity: 7,
        fallback: Some("NULL".to_string()),
    });

    // OpenVPN probe
    probes.push(Probe {
        name: "OpenVPN".to_string(),
        protocol: "udp".to_string(),
        data: vec![],
        ports: vec![1194],
        ssl_ports: vec![],
        rarity: 7,
        fallback: None,
    });

    // Mumble probe
    probes.push(Probe {
        name: "Mumble".to_string(),
        protocol: "tcp".to_string(),
        data: vec![],
        ports: vec![64738],
        ssl_ports: vec![],
        rarity: 7,
        fallback: Some("NULL".to_string()),
    });

    probes
}
