// Tier-based signature modules
pub mod tier1_common;
pub mod tier2_databases;
pub mod tier2_webservers;
pub mod tier2_mail;
pub mod tier2_queues;
pub mod tier2_monitoring;
pub mod tier3_cloud;
pub mod tier3_iot;
pub mod tier3_vpn;
pub mod tier3_specialized;

use nmap_core::{NmapError, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSignature {
    pub service_name: String,
    pub probe_name: String,
    pub pattern: String,
    pub version_info: Option<VersionInfo>,
    pub ports: Vec<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub product: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub os_type: Option<String>,
    pub device_type: Option<String>,
    pub cpe: Vec<String>,
}

/// Tiered signature database for efficient service detection
/// Signatures are organized by tier for optimal performance:
/// - Tier 1: Most common services (checked first)
/// - Tier 2: Specialized services by category (databases, webservers, mail)
/// - Tier 3: Cloud, enterprise, and less common services
#[derive(Debug)]
pub struct SignatureDatabase {
    // All signatures organized by tier
    tier1_signatures: Vec<ServiceSignature>,
    tier2_signatures: Vec<ServiceSignature>,
    tier3_signatures: Vec<ServiceSignature>,

    // Combined view for compatibility
    all_signatures: Vec<ServiceSignature>,

    // Indices for fast lookups
    compiled_patterns: HashMap<usize, Regex>,
    service_index: HashMap<String, Vec<usize>>,
    probe_index: HashMap<String, Vec<usize>>,
    port_index: HashMap<u16, Vec<usize>>,
}

impl SignatureDatabase {
    /// Load the default signature database with all tiers
    pub fn load_default() -> Result<Self> {
        Self::load_with_tiers(true, true, true)
    }

    /// Load signature database with selective tier loading
    /// This allows for performance optimization by loading only needed tiers
    pub fn load_with_tiers(load_tier1: bool, load_tier2: bool, load_tier3: bool) -> Result<Self> {
        let mut tier1_signatures = Vec::new();
        let mut tier2_signatures = Vec::new();
        let mut tier3_signatures = Vec::new();
        let mut all_signatures = Vec::new();

        // Load signatures in order of specificity (most specific first)
        // This ensures specific signatures match before generic fallbacks

        // Load Tier 2: Specialized services by category (most specific)
        if load_tier2 {
            let mut tier2 = Vec::new();
            tier2.extend(tier2_webservers::load_tier2_webserver_signatures());
            tier2.extend(tier2_databases::load_tier2_database_signatures());
            tier2.extend(tier2_mail::load_tier2_mail_signatures());
            tier2.extend(tier2_queues::load_tier2_queue_signatures());
            tier2.extend(tier2_monitoring::load_tier2_monitoring_signatures());

            tier2_signatures = tier2.clone();
            all_signatures.extend(tier2);
        }

        // Load Tier 3: Cloud, enterprise, and specialized services
        if load_tier3 {
            let mut tier3 = Vec::new();
            tier3.extend(tier3_cloud::load_tier3_cloud_signatures());
            tier3.extend(tier3_iot::load_tier3_iot_signatures());
            tier3.extend(tier3_vpn::load_tier3_vpn_signatures());
            tier3.extend(tier3_specialized::load_tier3_specialized_signatures());

            tier3_signatures = tier3.clone();
            all_signatures.extend(tier3);
        }

        // Load Tier 1: Common/generic services (checked last for fallback)
        if load_tier1 {
            tier1_signatures = tier1_common::load_tier1_signatures();
            all_signatures.extend(tier1_signatures.clone());
        }

        // Build indices for fast lookups
        let mut compiled_patterns = HashMap::new();
        let mut service_index = HashMap::new();
        let mut probe_index = HashMap::new();
        let mut port_index = HashMap::new();

        for (i, sig) in all_signatures.iter().enumerate() {
            // Compile regex pattern
            if let Ok(regex) = Regex::new(&sig.pattern) {
                compiled_patterns.insert(i, regex);
            }

            // Build service index
            service_index.entry(sig.service_name.clone())
                .or_insert_with(Vec::new)
                .push(i);

            // Build probe index
            probe_index.entry(sig.probe_name.clone())
                .or_insert_with(Vec::new)
                .push(i);

            // Build port index
            for &port in &sig.ports {
                port_index.entry(port)
                    .or_insert_with(Vec::new)
                    .push(i);
            }
        }

        Ok(Self {
            tier1_signatures,
            tier2_signatures,
            tier3_signatures,
            all_signatures,
            compiled_patterns,
            service_index,
            probe_index,
            port_index,
        })
    }

    /// Match a banner against signatures
    /// Searches in order: port-specific signatures, then all signatures
    pub fn match_banner(&self, banner: &str, port: u16, protocol: &str) -> Result<crate::ServiceInfo> {
        // Try to match banner against all signatures
        // First, try port-specific signatures for better accuracy
        if let Some(indices) = self.port_index.get(&port) {
            for &i in indices {
                let signature = &self.all_signatures[i];

                if signature.protocol != protocol {
                    continue;
                }

                if let Some(regex) = self.compiled_patterns.get(&i) {
                    if let Some(captures) = regex.captures(banner) {
                        return Ok(self.build_service_info(signature, &captures));
                    }
                }
            }
        }

        // Fall back to trying all signatures
        for (i, signature) in self.all_signatures.iter().enumerate() {
            if signature.protocol != protocol {
                continue;
            }

            if !signature.ports.is_empty() && !signature.ports.contains(&port) {
                continue;
            }

            if let Some(regex) = self.compiled_patterns.get(&i) {
                if let Some(captures) = regex.captures(banner) {
                    return Ok(self.build_service_info(signature, &captures));
                }
            }
        }

        Err(NmapError::Other("Service not detected".to_string()))
    }

    /// Match a probe response against signatures for a specific probe
    pub fn match_probe_response(
        &self,
        response: &str,
        probe_name: &str,
        port: u16,
        protocol: &str,
    ) -> Result<crate::ServiceInfo> {
        // Get signatures for this probe
        if let Some(indices) = self.probe_index.get(probe_name) {
            for &i in indices {
                let signature = &self.all_signatures[i];

                if signature.protocol != protocol {
                    continue;
                }

                if !signature.ports.is_empty() && !signature.ports.contains(&port) {
                    continue;
                }

                if let Some(regex) = self.compiled_patterns.get(&i) {
                    if let Some(captures) = regex.captures(response) {
                        return Ok(self.build_service_info(signature, &captures));
                    }
                }
            }
        }

        Err(NmapError::Other("Service not detected".to_string()))
    }

    /// Build ServiceInfo from a matched signature and regex captures
    fn build_service_info(&self, signature: &ServiceSignature, captures: &regex::Captures) -> crate::ServiceInfo {
        let mut service = crate::ServiceInfo {
            name: signature.service_name.clone(),
            product: None,
            version: None,
            extra_info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: Vec::new(),
            confidence: 95, // High confidence for regex matches
        };

        if let Some(ref version_info) = signature.version_info {
            service.product = version_info.product.as_ref().map(|p| self.substitute_captures(p, captures));
            service.version = version_info.version.as_ref().map(|v| self.substitute_captures(v, captures));
            service.extra_info = version_info.info.as_ref().map(|i| self.substitute_captures(i, captures));
            service.hostname = version_info.hostname.as_ref().map(|h| self.substitute_captures(h, captures));
            service.os_type = version_info.os_type.clone();
            service.device_type = version_info.device_type.clone();

            service.cpe = version_info.cpe.iter()
                .map(|cpe| self.substitute_captures(cpe, captures))
                .collect();
        }

        service
    }

    /// Substitute regex capture groups ($1, $2, etc.) in template strings
    fn substitute_captures(&self, template: &str, captures: &regex::Captures) -> String {
        let mut result = template.to_string();

        // Replace $1, $2, etc. with capture groups
        for i in 1..captures.len() {
            if let Some(capture) = captures.get(i) {
                let placeholder = format!("${}", i);
                result = result.replace(&placeholder, capture.as_str());
            }
        }

        result
    }

    // Query methods for signature information

    pub fn get_signatures_for_service(&self, service_name: &str) -> Vec<&ServiceSignature> {
        if let Some(indices) = self.service_index.get(service_name) {
            indices.iter().map(|&i| &self.all_signatures[i]).collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_signatures_for_probe(&self, probe_name: &str) -> Vec<&ServiceSignature> {
        if let Some(indices) = self.probe_index.get(probe_name) {
            indices.iter().map(|&i| &self.all_signatures[i]).collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_signatures_for_port(&self, port: u16) -> Vec<&ServiceSignature> {
        if let Some(indices) = self.port_index.get(&port) {
            indices.iter().map(|&i| &self.all_signatures[i]).collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_all_signatures(&self) -> &[ServiceSignature] {
        &self.all_signatures
    }

    pub fn get_signature_count(&self) -> usize {
        self.all_signatures.len()
    }

    pub fn get_tier_counts(&self) -> (usize, usize, usize) {
        (
            self.tier1_signatures.len(),
            self.tier2_signatures.len(),
            self.tier3_signatures.len(),
        )
    }

    pub fn get_service_categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self.service_index.keys().cloned().collect();
        categories.sort();
        categories
    }
}

impl Clone for SignatureDatabase {
    fn clone(&self) -> Self {
        // Note: Regex doesn't implement Clone, so we need to recompile
        let mut compiled_patterns = HashMap::new();
        for (i, signature) in self.all_signatures.iter().enumerate() {
            if let Ok(regex) = Regex::new(&signature.pattern) {
                compiled_patterns.insert(i, regex);
            }
        }

        Self {
            tier1_signatures: self.tier1_signatures.clone(),
            tier2_signatures: self.tier2_signatures.clone(),
            tier3_signatures: self.tier3_signatures.clone(),
            all_signatures: self.all_signatures.clone(),
            compiled_patterns,
            service_index: self.service_index.clone(),
            probe_index: self.probe_index.clone(),
            port_index: self.port_index.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_database_creation() {
        let db = SignatureDatabase::load_default().unwrap();
        assert!(!db.all_signatures.is_empty());
        assert!(!db.compiled_patterns.is_empty());
        println!("Loaded {} signatures", db.get_signature_count());
        assert!(db.get_signature_count() >= 100, "Should have 100+ signatures");
    }

    #[test]
    fn test_tier_loading() {
        let db_all = SignatureDatabase::load_default().unwrap();
        let (tier1, tier2, tier3) = db_all.get_tier_counts();

        println!("Tier 1: {} signatures", tier1);
        println!("Tier 2: {} signatures", tier2);
        println!("Tier 3: {} signatures", tier3);

        assert!(tier1 > 0, "Tier 1 should have signatures");
        assert!(tier2 > 0, "Tier 2 should have signatures");
        assert!(tier3 > 0, "Tier 3 should have signatures");

        let total = tier1 + tier2 + tier3;
        assert_eq!(total, db_all.get_signature_count(), "All tiers should sum to total");
    }

    #[test]
    fn test_selective_tier_loading() {
        // Load only tier 1
        let db_tier1 = SignatureDatabase::load_with_tiers(true, false, false).unwrap();
        let (t1, t2, t3) = db_tier1.get_tier_counts();
        assert!(t1 > 0);
        assert_eq!(t2, 0);
        assert_eq!(t3, 0);

        // Load tier 1 and 2
        let db_tier12 = SignatureDatabase::load_with_tiers(true, true, false).unwrap();
        let (t1, t2, t3) = db_tier12.get_tier_counts();
        assert!(t1 > 0);
        assert!(t2 > 0);
        assert_eq!(t3, 0);
    }

    #[test]
    fn test_match_apache_banner() {
        let db = SignatureDatabase::load_default().unwrap();

        let apache_banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n";
        let result = db.match_banner(apache_banner, 80, "tcp");
        assert!(result.is_ok());

        let service = result.unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product, Some("Apache httpd".to_string()));
        assert_eq!(service.version, Some("2.4.41".to_string()));
    }

    #[test]
    fn test_match_nginx_banner() {
        let db = SignatureDatabase::load_default().unwrap();

        let nginx_banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n";
        let result = db.match_banner(nginx_banner, 80, "tcp");
        assert!(result.is_ok());

        let service = result.unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product, Some("nginx".to_string()));
        assert_eq!(service.version, Some("1.18.0".to_string()));
    }

    #[test]
    fn test_match_ssh_banner() {
        let db = SignatureDatabase::load_default().unwrap();

        let ssh_banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3";
        let result = db.match_banner(ssh_banner, 22, "tcp");
        assert!(result.is_ok());

        let service = result.unwrap();
        assert_eq!(service.name, "ssh");
        assert_eq!(service.product, Some("OpenSSH".to_string()));
        assert_eq!(service.version, Some("8.2p1".to_string()));
    }

    #[test]
    fn test_match_mysql_banner() {
        let db = SignatureDatabase::load_default().unwrap();

        let mysql_banner = "5.7.33-0ubuntu0.18.04.1-MySQL";
        let result = db.match_banner(mysql_banner, 3306, "tcp");
        assert!(result.is_ok());

        let service = result.unwrap();
        assert_eq!(service.name, "mysql");
    }

    #[test]
    fn test_match_redis_banner() {
        let db = SignatureDatabase::load_default().unwrap();

        let redis_banner = "$256\r\n# Server\r\nredis_version:6.2.5\r\n";
        let result = db.match_banner(redis_banner, 6379, "tcp");
        assert!(result.is_ok());

        let service = result.unwrap();
        assert_eq!(service.name, "redis");
        assert_eq!(service.product, Some("Redis".to_string()));
        assert_eq!(service.version, Some("6.2.5".to_string()));
    }

    #[test]
    fn test_get_signatures_for_port() {
        let db = SignatureDatabase::load_default().unwrap();

        let http_sigs = db.get_signatures_for_port(80);
        assert!(!http_sigs.is_empty());

        let ssh_sigs = db.get_signatures_for_port(22);
        assert!(!ssh_sigs.is_empty());
    }

    #[test]
    fn test_get_service_categories() {
        let db = SignatureDatabase::load_default().unwrap();

        let categories = db.get_service_categories();
        assert!(!categories.is_empty());

        // Should include major service types
        assert!(categories.contains(&"http".to_string()));
        assert!(categories.contains(&"ssh".to_string()));
        assert!(categories.contains(&"ftp".to_string()));
        assert!(categories.contains(&"smtp".to_string()));
        assert!(categories.contains(&"mysql".to_string()));
    }

    #[test]
    fn test_no_match() {
        let db = SignatureDatabase::load_default().unwrap();

        let unknown_banner = "UNKNOWN PROTOCOL XYZ123";
        let result = db.match_banner(unknown_banner, 12345, "tcp");
        assert!(result.is_err());
    }
}
