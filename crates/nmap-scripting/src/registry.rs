/// Script Registry - Registers all vulnerability detection scripts
use super::engine::*;
use super::vuln_http::*;
use super::vuln_ssl::*;
use super::vuln_smb::*;
use super::vuln_services::*;
use super::vuln_network::*;
use super::builtin_scripts::*;
use anyhow::Result;

/// Register all built-in and vulnerability scripts with the engine
pub async fn register_all_scripts(engine: &ScriptEngine) -> Result<()> {
    // Built-in discovery scripts
    engine.register_script(Box::new(HttpTitleScript)).await?;
    engine.register_script(Box::new(SshVersionScript)).await?;
    engine.register_script(Box::new(FtpBannerScript)).await?;
    engine.register_script(Box::new(SmtpCommandsScript)).await?;
    engine.register_script(Box::new(DnsVersionScript)).await?;

    // HTTP Vulnerability Scripts
    engine.register_script(Box::new(ApachePathTraversal)).await?;
    engine.register_script(Box::new(Struts2RCE)).await?;
    engine.register_script(Box::new(HttpDefaultAccounts)).await?;
    engine.register_script(Box::new(HttpSQLInjection)).await?;
    engine.register_script(Box::new(HttpSecurityHeaders)).await?;

    // SSL/TLS Vulnerability Scripts
    engine.register_script(Box::new(SSLHeartbleed)).await?;
    engine.register_script(Box::new(SSLPoodle)).await?;
    engine.register_script(Box::new(SSLCertExpiry)).await?;

    // SMB Vulnerability Scripts
    engine.register_script(Box::new(SMBEternalBlue)).await?;
    engine.register_script(Box::new(SMBMS08067)).await?;

    // Service-Specific Vulnerability Scripts
    engine.register_script(Box::new(SSHWeakAlgorithms)).await?;
    engine.register_script(Box::new(FTPAnonymous)).await?;
    engine.register_script(Box::new(MySQLEmptyPassword)).await?;
    engine.register_script(Box::new(TelnetEncryption)).await?;

    // Network Service Vulnerability Scripts
    engine.register_script(Box::new(DNSZoneTransfer)).await?;
    engine.register_script(Box::new(SMTPOpenRelay)).await?;
    engine.register_script(Box::new(NTPMonlist)).await?;
    engine.register_script(Box::new(SNMPDefaultCommunity)).await?;
    engine.register_script(Box::new(RDPMS12020)).await?;
    engine.register_script(Box::new(HttpXSSDetection)).await?;

    tracing::info!("Registered {} vulnerability detection scripts",
                   engine.list_scripts().await.len());

    Ok(())
}

/// Get recommended scripts for a specific service
pub fn get_scripts_for_service(service: &str) -> Vec<&'static str> {
    match service {
        "http" | "http-proxy" => vec![
            "http-vuln-cve2021-41773",
            "http-vuln-cve2017-5638",
            "http-default-accounts",
            "http-sql-injection",
            "http-xss-detection",
            "http-security-headers",
            "http-title",
        ],
        "https" | "ssl" => vec![
            "http-vuln-cve2021-41773",
            "http-vuln-cve2017-5638",
            "http-default-accounts",
            "http-sql-injection",
            "http-xss-detection",
            "http-security-headers",
            "http-title",
            "ssl-heartbleed",
            "ssl-poodle",
            "ssl-cert-expiry",
        ],
        "ssh" => vec![
            "ssh-weak-algorithms",
            "ssh-version",
        ],
        "ftp" => vec![
            "ftp-anon",
            "ftp-banner",
        ],
        "smtp" => vec![
            "smtp-open-relay",
            "smtp-commands",
        ],
        "mysql" => vec![
            "mysql-empty-password",
        ],
        "microsoft-ds" | "smb" => vec![
            "smb-vuln-ms17-010",
            "smb-vuln-ms08-067",
        ],
        "dns" => vec![
            "dns-zone-transfer",
            "dns-version",
        ],
        "ntp" => vec![
            "ntp-monlist",
        ],
        "snmp" => vec![
            "snmp-default-community",
        ],
        "ms-wbt-server" | "rdp" => vec![
            "rdp-vuln-ms12-020",
        ],
        "telnet" => vec![
            "telnet-encryption",
        ],
        _ => vec![],
    }
}

/// Get all vulnerability scanning scripts
pub fn get_vulnerability_scripts() -> Vec<&'static str> {
    vec![
        // HTTP
        "http-vuln-cve2021-41773",
        "http-vuln-cve2017-5638",
        "http-default-accounts",
        "http-sql-injection",
        "http-xss-detection",
        "http-security-headers",
        // SSL/TLS
        "ssl-heartbleed",
        "ssl-poodle",
        "ssl-cert-expiry",
        // SMB
        "smb-vuln-ms17-010",
        "smb-vuln-ms08-067",
        // Services
        "ssh-weak-algorithms",
        "ftp-anon",
        "mysql-empty-password",
        "telnet-encryption",
        // Network
        "dns-zone-transfer",
        "smtp-open-relay",
        "ntp-monlist",
        "snmp-default-community",
        "rdp-vuln-ms12-020",
    ]
}

/// Get safe discovery scripts (non-intrusive)
pub fn get_safe_scripts() -> Vec<&'static str> {
    vec![
        "http-title",
        "http-security-headers",
        "ssh-version",
        "ssh-weak-algorithms",
        "ftp-banner",
        "smtp-commands",
        "dns-version",
        "ssl-cert-expiry",
        "ssl-heartbleed",
        "ssl-poodle",
        "smb-vuln-ms17-010",
        "telnet-encryption",
        "ntp-monlist",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_all_scripts() {
        let engine = ScriptEngine::new();
        let result = register_all_scripts(&engine).await;
        assert!(result.is_ok());

        let scripts = engine.list_scripts().await;
        assert!(scripts.len() >= 20, "Should have at least 20 scripts registered");
    }

    #[test]
    fn test_get_scripts_for_service() {
        let http_scripts = get_scripts_for_service("http");
        assert!(!http_scripts.is_empty());
        assert!(http_scripts.contains(&"http-title"));

        let ssh_scripts = get_scripts_for_service("ssh");
        assert!(ssh_scripts.contains(&"ssh-weak-algorithms"));
    }

    #[test]
    fn test_get_vulnerability_scripts() {
        let vuln_scripts = get_vulnerability_scripts();
        assert_eq!(vuln_scripts.len(), 20);
    }
}
