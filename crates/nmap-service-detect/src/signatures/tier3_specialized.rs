use crate::signatures::{ServiceSignature, VersionInfo};

/// Tier 3 Specialized Services - Blockchain, gaming, voice, and legacy protocol signatures
/// Covers cryptocurrency nodes, game servers, VoIP, and legacy protocols
pub fn load_tier3_specialized_signatures() -> Vec<ServiceSignature> {
    let mut signatures = Vec::new();

    // ========== BLOCKCHAIN & CRYPTOCURRENCY ==========

    // Bitcoin Core
    signatures.push(ServiceSignature {
        service_name: "bitcoin".to_string(),
        probe_name: "Bitcoin".to_string(),
        pattern: r"bitcoin".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Bitcoin Core".to_string()),
            version: None,
            info: Some("Bitcoin P2P network node".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:bitcoin:bitcoin_core".to_string()],
        }),
        ports: vec![8333, 8332],
        protocol: "tcp".to_string(),
    });

    // Ethereum (geth)
    signatures.push(ServiceSignature {
        service_name: "ethereum-geth".to_string(),
        probe_name: "Ethereum".to_string(),
        pattern: r"Geth".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Go Ethereum".to_string()),
            version: None,
            info: Some("Ethereum node client".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ethereum:go_ethereum".to_string()],
        }),
        ports: vec![30303, 8545, 8546],
        protocol: "tcp".to_string(),
    });

    // Ethereum JSON-RPC
    signatures.push(ServiceSignature {
        service_name: "ethereum-rpc".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""jsonrpc":"2.0".*eth_"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Ethereum JSON-RPC".to_string()),
            version: None,
            info: Some("Ethereum API endpoint".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ethereum:json_rpc".to_string()],
        }),
        ports: vec![8545, 8546],
        protocol: "tcp".to_string(),
    });

    // IPFS (InterPlanetary File System)
    signatures.push(ServiceSignature {
        service_name: "ipfs".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"ipfs|Kubo".to_string(),
        version_info: Some(VersionInfo {
            product: Some("IPFS".to_string()),
            version: None,
            info: Some("Distributed file system".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ipfs:ipfs".to_string()],
        }),
        ports: vec![4001, 5001, 8080],
        protocol: "tcp".to_string(),
    });

    // Monero Node
    signatures.push(ServiceSignature {
        service_name: "monero".to_string(),
        probe_name: "Monero".to_string(),
        pattern: r"monero".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Monero".to_string()),
            version: None,
            info: Some("Privacy-focused cryptocurrency".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:getmonero:monero".to_string()],
        }),
        ports: vec![18080, 18081],
        protocol: "tcp".to_string(),
    });

    // ========== GAMING SERVERS ==========

    // Minecraft Server
    signatures.push(ServiceSignature {
        service_name: "minecraft".to_string(),
        probe_name: "Minecraft".to_string(),
        pattern: r"\xfe\x01|\x00.*minecraft".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Minecraft Server".to_string()),
            version: None,
            info: Some("Game server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mojang:minecraft_server".to_string()],
        }),
        ports: vec![25565],
        protocol: "tcp".to_string(),
    });

    // Minecraft RCON
    signatures.push(ServiceSignature {
        service_name: "minecraft-rcon".to_string(),
        probe_name: "RCON".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Minecraft RCON".to_string()),
            version: None,
            info: Some("Remote console".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mojang:minecraft_rcon".to_string()],
        }),
        ports: vec![25575],
        protocol: "tcp".to_string(),
    });

    // Steam Game Server
    signatures.push(ServiceSignature {
        service_name: "steam-gameserver".to_string(),
        probe_name: "Steam".to_string(),
        pattern: r"Source Engine|valve".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Steam Game Server".to_string()),
            version: None,
            info: Some("Valve game server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:valvesoftware:steam".to_string()],
        }),
        ports: vec![27015, 27016, 27017],
        protocol: "udp".to_string(),
    });

    // TeamSpeak 3
    signatures.push(ServiceSignature {
        service_name: "teamspeak3".to_string(),
        probe_name: "TeamSpeak".to_string(),
        pattern: r"TeamSpeak.*3".to_string(),
        version_info: Some(VersionInfo {
            product: Some("TeamSpeak 3".to_string()),
            version: None,
            info: Some("Voice communication server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:teamspeak:teamspeak3".to_string()],
        }),
        ports: vec![9987, 10011, 30033],
        protocol: "udp".to_string(),
    });

    // Mumble Server
    signatures.push(ServiceSignature {
        service_name: "mumble".to_string(),
        probe_name: "Mumble".to_string(),
        pattern: r"Mumble".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Mumble Server".to_string()),
            version: None,
            info: Some("Low-latency voice chat".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mumble:mumble".to_string()],
        }),
        ports: vec![64738],
        protocol: "tcp".to_string(),
    });

    // Discord Bot
    signatures.push(ServiceSignature {
        service_name: "discord-bot".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"discord.*bot".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Discord Bot".to_string()),
            version: None,
            info: Some("Chat bot service".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:discord:bot".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // ========== VOICE & TELEPHONY ==========

    // SIP (Session Initiation Protocol)
    signatures.push(ServiceSignature {
        service_name: "sip".to_string(),
        probe_name: "SIP".to_string(),
        pattern: r"SIP/2\.0".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SIP".to_string()),
            version: None,
            info: Some("VoIP signaling protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ietf:sip".to_string()],
        }),
        ports: vec![5060, 5061],
        protocol: "tcp".to_string(),
    });

    // Asterisk PBX
    signatures.push(ServiceSignature {
        service_name: "asterisk".to_string(),
        probe_name: "SIP".to_string(),
        pattern: r"Asterisk.*PBX".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Asterisk PBX".to_string()),
            version: None,
            info: Some("Open source PBX".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:digium:asterisk".to_string()],
        }),
        ports: vec![5060, 5061],
        protocol: "tcp".to_string(),
    });

    // FreeSWITCH
    signatures.push(ServiceSignature {
        service_name: "freeswitch".to_string(),
        probe_name: "SIP".to_string(),
        pattern: r"FreeSWITCH".to_string(),
        version_info: Some(VersionInfo {
            product: Some("FreeSWITCH".to_string()),
            version: None,
            info: Some("Telephony platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:freeswitch:freeswitch".to_string()],
        }),
        ports: vec![5060, 5080],
        protocol: "tcp".to_string(),
    });

    // RTP (Real-time Transport Protocol)
    signatures.push(ServiceSignature {
        service_name: "rtp".to_string(),
        probe_name: "RTP".to_string(),
        pattern: r"\x80[\x00-\xff]".to_string(),
        version_info: Some(VersionInfo {
            product: Some("RTP".to_string()),
            version: None,
            info: Some("Media streaming protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ietf:rtp".to_string()],
        }),
        ports: vec![],
        protocol: "udp".to_string(),
    });

    // Jitsi Meet
    signatures.push(ServiceSignature {
        service_name: "jitsi".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Jitsi Meet".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Jitsi Meet".to_string()),
            version: None,
            info: Some("Video conferencing".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:jitsi:jitsi_meet".to_string()],
        }),
        ports: vec![8080, 443],
        protocol: "tcp".to_string(),
    });

    // ========== LEGACY PROTOCOLS ==========

    // Telnet
    signatures.push(ServiceSignature {
        service_name: "telnet".to_string(),
        probe_name: "NULL".to_string(),
        pattern: r"\xff[\xfb-\xfe]".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Telnet".to_string()),
            version: None,
            info: Some("Legacy remote access".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:telnet:telnet".to_string()],
        }),
        ports: vec![23],
        protocol: "tcp".to_string(),
    });

    // rlogin
    signatures.push(ServiceSignature {
        service_name: "rlogin".to_string(),
        probe_name: "rlogin".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("rlogin".to_string()),
            version: None,
            info: Some("Berkeley remote login".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:berkeley:rlogin".to_string()],
        }),
        ports: vec![513],
        protocol: "tcp".to_string(),
    });

    // rsh (Remote Shell)
    signatures.push(ServiceSignature {
        service_name: "rsh".to_string(),
        probe_name: "rsh".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("rsh".to_string()),
            version: None,
            info: Some("Berkeley remote shell".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:berkeley:rsh".to_string()],
        }),
        ports: vec![514],
        protocol: "tcp".to_string(),
    });

    // rexec
    signatures.push(ServiceSignature {
        service_name: "rexec".to_string(),
        probe_name: "rexec".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("rexec".to_string()),
            version: None,
            info: Some("Remote execution".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:berkeley:rexec".to_string()],
        }),
        ports: vec![512],
        protocol: "tcp".to_string(),
    });

    // X11
    signatures.push(ServiceSignature {
        service_name: "x11".to_string(),
        probe_name: "X11".to_string(),
        pattern: r"^[BNl]".to_string(),
        version_info: Some(VersionInfo {
            product: Some("X11".to_string()),
            version: None,
            info: Some("X Window System".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:x:x11".to_string()],
        }),
        ports: vec![6000, 6001, 6002, 6003],
        protocol: "tcp".to_string(),
    });

    // Finger
    signatures.push(ServiceSignature {
        service_name: "finger".to_string(),
        probe_name: "Finger".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Finger".to_string()),
            version: None,
            info: Some("User information lookup".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:finger:finger".to_string()],
        }),
        ports: vec![79],
        protocol: "tcp".to_string(),
    });

    // ========== STREAMING & MEDIA ==========

    // Icecast
    signatures.push(ServiceSignature {
        service_name: "icecast".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Icecast".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Icecast".to_string()),
            version: None,
            info: Some("Streaming media server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:icecast:icecast".to_string()],
        }),
        ports: vec![8000],
        protocol: "tcp".to_string(),
    });

    // Shoutcast
    signatures.push(ServiceSignature {
        service_name: "shoutcast".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"SHOUTcast".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SHOUTcast".to_string()),
            version: None,
            info: Some("Internet radio server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nullsoft:shoutcast".to_string()],
        }),
        ports: vec![8000],
        protocol: "tcp".to_string(),
    });

    // Plex Media Server
    signatures.push(ServiceSignature {
        service_name: "plex".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Plex".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Plex Media Server".to_string()),
            version: None,
            info: Some("Media streaming server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:plex:plex_media_server".to_string()],
        }),
        ports: vec![32400],
        protocol: "tcp".to_string(),
    });

    // Emby Server
    signatures.push(ServiceSignature {
        service_name: "emby".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Emby Server".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Emby Server".to_string()),
            version: None,
            info: Some("Media server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:emby:emby_server".to_string()],
        }),
        ports: vec![8096],
        protocol: "tcp".to_string(),
    });

    // Jellyfin
    signatures.push(ServiceSignature {
        service_name: "jellyfin".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Jellyfin".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Jellyfin".to_string()),
            version: None,
            info: Some("Free media server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:jellyfin:jellyfin".to_string()],
        }),
        ports: vec![8096],
        protocol: "tcp".to_string(),
    });

    // ========== FILE SHARING ==========

    // BitTorrent Tracker
    signatures.push(ServiceSignature {
        service_name: "bittorrent-tracker".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"d8:completei|announce".to_string(),
        version_info: Some(VersionInfo {
            product: Some("BitTorrent Tracker".to_string()),
            version: None,
            info: Some("Torrent tracker".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:bittorrent:tracker".to_string()],
        }),
        ports: vec![6969, 8080],
        protocol: "tcp".to_string(),
    });

    // Transmission (BitTorrent client)
    signatures.push(ServiceSignature {
        service_name: "transmission".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Transmission".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Transmission".to_string()),
            version: None,
            info: Some("BitTorrent client".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:transmissionbt:transmission".to_string()],
        }),
        ports: vec![9091],
        protocol: "tcp".to_string(),
    });

    // Syncthing
    signatures.push(ServiceSignature {
        service_name: "syncthing".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Syncthing".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Syncthing".to_string()),
            version: None,
            info: Some("Continuous file synchronization".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:syncthing:syncthing".to_string()],
        }),
        ports: vec![8384, 22000],
        protocol: "tcp".to_string(),
    });

    signatures
}
