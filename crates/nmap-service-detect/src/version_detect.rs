use crate::{ServiceInfo, ServiceDetector, ServiceDetectionOptions};
use nmap_core::Result;
use nmap_net::Host;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::time::Duration;

#[derive(Debug, Clone)]
pub struct VersionScanResult {
    pub target: IpAddr,
    pub services: HashMap<u16, ServiceInfo>,
    pub scan_time: Duration,
    pub total_ports: usize,
    pub detected_services: usize,
}

pub struct VersionDetector {
    service_detector: ServiceDetector,
    options: ServiceDetectionOptions,
}

impl VersionDetector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            service_detector: ServiceDetector::new()?,
            options: ServiceDetectionOptions::default(),
        })
    }

    pub fn with_options(mut self, options: ServiceDetectionOptions) -> Self {
        self.options = options.clone();
        self.service_detector = self.service_detector.with_options(options);
        self
    }

    pub async fn scan_version(&self, target: &Host, open_ports: &[(u16, String)]) -> Result<VersionScanResult> {
        let start_time = std::time::Instant::now();
        let ip = target.address;
        
        let mut services = HashMap::new();
        let mut detected_count = 0;

        // Filter ports based on version intensity
        let ports_to_scan = self.filter_ports_by_intensity(open_ports);

        // Perform service detection on filtered ports
        let results = self.service_detector.detect_services_batch(target, &ports_to_scan).await?;

        for result in results {
            if let Some(service) = result.service {
                services.insert(result.port, service);
                detected_count += 1;
            }
        }

        Ok(VersionScanResult {
            target: ip,
            services,
            scan_time: start_time.elapsed(),
            total_ports: ports_to_scan.len(),
            detected_services: detected_count,
        })
    }

    pub async fn scan_version_aggressive(&self, target: &Host, open_ports: &[(u16, String)]) -> Result<VersionScanResult> {
        // Aggressive version detection with all probes
        let mut aggressive_options = self.options.clone();
        aggressive_options.version_intensity = 9;
        aggressive_options.version_all = true;
        aggressive_options.timeout = Duration::from_secs(10);

        let aggressive_detector = self.service_detector.clone().with_options(aggressive_options);
        let start_time = std::time::Instant::now();
        let ip = target.address;
        
        let mut services = HashMap::new();
        let mut detected_count = 0;

        // Use all ports for aggressive scan
        let results = aggressive_detector.detect_services_batch(target, open_ports).await?;

        for result in results {
            if let Some(service) = result.service {
                services.insert(result.port, service);
                detected_count += 1;
            }
        }

        Ok(VersionScanResult {
            target: ip,
            services,
            scan_time: start_time.elapsed(),
            total_ports: open_ports.len(),
            detected_services: detected_count,
        })
    }

    pub async fn scan_version_light(&self, target: &Host, open_ports: &[(u16, String)]) -> Result<VersionScanResult> {
        // Light version detection with minimal probes
        let mut light_options = self.options.clone();
        light_options.version_intensity = 2;
        light_options.version_light = true;
        light_options.timeout = Duration::from_secs(2);

        let light_detector = self.service_detector.clone().with_options(light_options);
        let start_time = std::time::Instant::now();
        let ip = target.address;
        
        let mut services = HashMap::new();
        let mut detected_count = 0;

        // Filter to only common ports for light scan
        let common_ports = self.filter_common_ports(open_ports);
        let results = light_detector.detect_services_batch(target, &common_ports).await?;

        for result in results {
            if let Some(service) = result.service {
                services.insert(result.port, service);
                detected_count += 1;
            }
        }

        Ok(VersionScanResult {
            target: ip,
            services,
            scan_time: start_time.elapsed(),
            total_ports: common_ports.len(),
            detected_services: detected_count,
        })
    }

    fn filter_ports_by_intensity(&self, ports: &[(u16, String)]) -> Vec<(u16, String)> {
        match self.options.version_intensity {
            0..=2 => self.filter_common_ports(ports),
            3..=5 => self.filter_standard_ports(ports),
            6..=7 => ports.to_vec(), // All provided ports
            8..=9 => {
                // Include additional uncommon ports
                let mut filtered = ports.to_vec();
                // Add some uncommon ports if not already present
                let uncommon_ports = vec![
                    (8000, "tcp".to_string()),
                    (8008, "tcp".to_string()),
                    (8080, "tcp".to_string()),
                    (8888, "tcp".to_string()),
                    (9000, "tcp".to_string()),
                ];
                
                for (port, proto) in uncommon_ports {
                    if !filtered.iter().any(|(p, pr)| *p == port && pr == &proto) {
                        filtered.push((port, proto));
                    }
                }
                filtered
            }
            _ => ports.to_vec(),
        }
    }

    fn filter_common_ports(&self, ports: &[(u16, String)]) -> Vec<(u16, String)> {
        let common_tcp_ports = vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900
        ];
        let common_udp_ports = vec![53, 67, 68, 123, 135, 137, 138, 161, 162, 445, 631, 1434];

        ports.iter()
            .filter(|(port, protocol)| {
                match protocol.as_str() {
                    "tcp" => common_tcp_ports.contains(port),
                    "udp" => common_udp_ports.contains(port),
                    _ => false,
                }
            })
            .cloned()
            .collect()
    }

    fn filter_standard_ports(&self, ports: &[(u16, String)]) -> Vec<(u16, String)> {
        let standard_tcp_ports = vec![
            20, 21, 22, 23, 25, 53, 79, 80, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144,
            179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
            631, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726,
            749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902,
            903, 911, 912, 981, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011,
            1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033,
            1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046,
            1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059,
            1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072,
            1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080
        ];

        ports.iter()
            .filter(|(port, protocol)| {
                match protocol.as_str() {
                    "tcp" => standard_tcp_ports.contains(port) || *port <= 1024,
                    "udp" => *port <= 1024,
                    _ => false,
                }
            })
            .cloned()
            .collect()
    }

    pub fn get_service_summary(&self, result: &VersionScanResult) -> String {
        let mut summary = format!(
            "Version scan completed for {} in {:.2}s\n",
            result.target,
            result.scan_time.as_secs_f64()
        );
        
        summary.push_str(&format!(
            "Scanned {} ports, detected {} services\n\n",
            result.total_ports,
            result.detected_services
        ));

        let mut sorted_ports: Vec<_> = result.services.iter().collect();
        sorted_ports.sort_by_key(|(port, _)| *port);

        for (port, service) in sorted_ports {
            summary.push_str(&format!("{}/tcp open {}", port, service.name));
            
            if let Some(ref product) = service.product {
                summary.push_str(&format!(" {}", product));
                
                if let Some(ref version) = service.version {
                    summary.push_str(&format!(" {}", version));
                }
            }
            
            if let Some(ref extra) = service.extra_info {
                summary.push_str(&format!(" ({})", extra));
            }
            
            summary.push('\n');
        }

        summary
    }
}

impl Default for VersionDetector {
    fn default() -> Self {
        Self::new().expect("Failed to create default version detector")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_version_detector_creation() {
        let detector = VersionDetector::new();
        assert!(detector.is_ok());
    }

    #[test]
    fn test_filter_common_ports() {
        let detector = VersionDetector::new().unwrap();
        let all_ports = vec![
            (22, "tcp".to_string()),
            (80, "tcp".to_string()),
            (12345, "tcp".to_string()),
            (53, "udp".to_string()),
            (54321, "udp".to_string()),
        ];
        
        let common = detector.filter_common_ports(&all_ports);
        assert_eq!(common.len(), 3); // 22, 80, 53
        assert!(common.contains(&(22, "tcp".to_string())));
        assert!(common.contains(&(80, "tcp".to_string())));
        assert!(common.contains(&(53, "udp".to_string())));
        assert!(!common.contains(&(12345, "tcp".to_string())));
    }

    #[test]
    fn test_filter_ports_by_intensity() {
        let all_ports = vec![
            (22, "tcp".to_string()),
            (80, "tcp".to_string()),
            (12345, "tcp".to_string()),
        ];

        // Low intensity should filter to common ports only
        let detector = VersionDetector::new().unwrap();
        let mut options = ServiceDetectionOptions::default();
        options.version_intensity = 2;
        let light_detector = detector.with_options(options);
        let filtered = light_detector.filter_ports_by_intensity(&all_ports);
        assert!(filtered.len() <= all_ports.len());

        // High intensity should include all ports
        let detector = VersionDetector::new().unwrap();
        let mut options = ServiceDetectionOptions::default();
        options.version_intensity = 7;
        let aggressive_detector = detector.with_options(options);
        let filtered = aggressive_detector.filter_ports_by_intensity(&all_ports);
        assert_eq!(filtered.len(), all_ports.len());
    }
}