use crate::signatures::{ServiceSignature, VersionInfo};

/// Tier 2 Mail Servers - SMTP, IMAP, and POP3 server implementations
/// Loaded after tier1 common mail signatures
pub fn load_tier2_mail_signatures() -> Vec<ServiceSignature> {
    let mut signatures = Vec::new();

    // ========== SMTP SERVERS ==========

    // Postfix
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*Postfix".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Postfix smtpd".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:postfix:postfix".to_string()],
        }),
        ports: vec![25, 587],
        protocol: "tcp".to_string(),
    });

    // Sendmail
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*Sendmail ([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Sendmail smtpd".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:sendmail:sendmail:$1".to_string()],
        }),
        ports: vec![25, 587],
        protocol: "tcp".to_string(),
    });

    // Exim
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*Exim ([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Exim smtpd".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:exim:exim:$1".to_string()],
        }),
        ports: vec![25, 587],
        protocol: "tcp".to_string(),
    });

    // Microsoft Exchange
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*Microsoft ESMTP MAIL Service".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Microsoft Exchange smtpd".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: Some("Windows".to_string()),
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:exchange_server".to_string()],
        }),
        ports: vec![25, 587],
        protocol: "tcp".to_string(),
    });

    // qmail
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*qmail".to_string(),
        version_info: Some(VersionInfo {
            product: Some("qmail smtpd".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:qmail:qmail".to_string()],
        }),
        ports: vec![25, 587],
        protocol: "tcp".to_string(),
    });

    // ========== IMAP SERVERS ==========

    // Dovecot
    signatures.push(ServiceSignature {
        service_name: "imap".to_string(),
        probe_name: "IMAP".to_string(),
        pattern: r"Dovecot.*ready".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Dovecot imapd".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:dovecot:dovecot".to_string()],
        }),
        ports: vec![143, 993],
        protocol: "tcp".to_string(),
    });

    // Courier
    signatures.push(ServiceSignature {
        service_name: "imap".to_string(),
        probe_name: "IMAP".to_string(),
        pattern: r"Courier-IMAP".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Courier imapd".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:courier:courier_imap".to_string()],
        }),
        ports: vec![143, 993],
        protocol: "tcp".to_string(),
    });

    // Cyrus
    signatures.push(ServiceSignature {
        service_name: "imap".to_string(),
        probe_name: "IMAP".to_string(),
        pattern: r"Cyrus.*IMAP.*v([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Cyrus imapd".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:cmu:cyrus_imap_server:$1".to_string()],
        }),
        ports: vec![143, 993],
        protocol: "tcp".to_string(),
    });

    // ========== MODERN SMTP SERVERS ==========

    // Haraka (Node.js SMTP)
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*Haraka".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Haraka".to_string()),
            version: None,
            info: Some("Node.js SMTP server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:haraka:haraka".to_string()],
        }),
        ports: vec![25, 587],
        protocol: "tcp".to_string(),
    });

    // ========== TESTING MAIL SERVERS ==========

    // MailHog
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*MailHog".to_string(),
        version_info: Some(VersionInfo {
            product: Some("MailHog".to_string()),
            version: None,
            info: Some("Email testing tool".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mailhog:mailhog".to_string()],
        }),
        ports: vec![1025, 8025],
        protocol: "tcp".to_string(),
    });

    // Mailpit
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*Mailpit".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Mailpit".to_string()),
            version: None,
            info: Some("Email testing tool".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mailpit:mailpit".to_string()],
        }),
        ports: vec![1025, 8025],
        protocol: "tcp".to_string(),
    });

    // ========== INTEGRATED MAIL SOLUTIONS ==========

    // Mailu
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*Mailu".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Mailu".to_string()),
            version: None,
            info: Some("Docker-based mail server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mailu:mailu".to_string()],
        }),
        ports: vec![25, 587, 465],
        protocol: "tcp".to_string(),
    });

    // iRedMail
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*iRedMail".to_string(),
        version_info: Some(VersionInfo {
            product: Some("iRedMail".to_string()),
            version: None,
            info: Some("Full-featured mail server solution".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:iredmail:iredmail".to_string()],
        }),
        ports: vec![25, 587, 465],
        protocol: "tcp".to_string(),
    });

    // Zimbra
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*Zimbra".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Zimbra Collaboration Suite".to_string()),
            version: None,
            info: Some("Groupware server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:zimbra:collaboration_suite".to_string()],
        }),
        ports: vec![25, 587, 7071],
        protocol: "tcp".to_string(),
    });

    // Kerio Connect
    signatures.push(ServiceSignature {
        service_name: "smtp".to_string(),
        probe_name: "SMTP".to_string(),
        pattern: r"220.*Kerio Connect".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kerio Connect".to_string()),
            version: None,
            info: Some("Email and collaboration server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:kerio:connect".to_string()],
        }),
        ports: vec![25, 587, 465],
        protocol: "tcp".to_string(),
    });

    signatures
}
