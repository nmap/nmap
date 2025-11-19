//! Example: Multi-Source OS Detection
//!
//! This example demonstrates how to use all three OS detection methods
//! (passive, app-layer, and active) and combine them with evidence fusion.

use nmap_os_detect::{
    PassiveDetector, AppLayerDetector, EvidenceFusion,
    Evidence, EvidenceSource, FusionOSHint,
};
use std::collections::HashMap;

fn main() {
    println!("=== Multi-Source OS Detection Example ===\n");

    // 1. Passive Detection (from SYN packet)
    println!("1. Passive Detection (p0f-style):");
    let passive = PassiveDetector::new();
    println!("   Loaded {} passive signatures", passive.signature_count());

    // Example: Analyzing a SYN packet
    let ttl = 64;
    let window = 64240;
    let mss = Some(1460);

    if let Some(hint) = passive.detect(ttl, window, mss) {
        println!("   TTL={}, Window={}, MSS={:?}", ttl, window, mss);
        println!("   → Detected: {} ({})", hint.name, hint.family);
        println!("   → Confidence: {}%\n", hint.confidence);
    }

    // 2. Application-Layer Detection
    println!("2. Application-Layer Detection:");
    let app_layer = AppLayerDetector::new();

    // SSH Banner
    let ssh_banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
    if let Some(hint) = app_layer.detect_from_ssh(ssh_banner) {
        println!("   SSH Banner: {}", ssh_banner);
        println!("   → Detected: {} ({})", hint.name, hint.family);
        println!("   → Confidence: {}%", hint.confidence);
    }

    // HTTP Headers
    let mut headers = HashMap::new();
    headers.insert("Server".to_string(), "Apache/2.4.41 (Ubuntu)".to_string());
    if let Some(hint) = app_layer.detect_from_http(&headers) {
        println!("\n   HTTP Server: Apache/2.4.41 (Ubuntu)");
        println!("   → Detected: {} ({})", hint.name, hint.family);
        println!("   → Confidence: {}%", hint.confidence);
    }

    // SMB Dialect
    let smb_dialect = "SMB 3.1.1";
    if let Some(hint) = app_layer.detect_from_smb(smb_dialect) {
        println!("\n   SMB Dialect: {}", smb_dialect);
        println!("   → Detected: {} ({})", hint.name, hint.family);
        println!("   → Confidence: {}%\n", hint.confidence);
    }

    // 3. Evidence Fusion
    println!("3. Multi-Source Evidence Fusion:");
    let fusion = EvidenceFusion::new();

    // Collect evidence from multiple sources
    let evidence = vec![
        Evidence {
            source: EvidenceSource::PassiveFingerprint,
            hint: FusionOSHint {
                name: "Ubuntu Linux 20.04".to_string(),
                family: "Linux".to_string(),
                confidence: 85,
            },
        },
        Evidence {
            source: EvidenceSource::SshBanner,
            hint: FusionOSHint {
                name: "Ubuntu Linux 20.04".to_string(),
                family: "Linux".to_string(),
                confidence: 85,
            },
        },
        Evidence {
            source: EvidenceSource::HttpHeaders,
            hint: FusionOSHint {
                name: "Ubuntu Linux".to_string(),
                family: "Linux".to_string(),
                confidence: 75,
            },
        },
    ];

    println!("   Sources: Passive, SSH, HTTP");
    println!("   Has consensus? {}", fusion.has_consensus(&evidence));
    println!("   Most likely family: {:?}", fusion.most_likely_family(&evidence));

    // Combine evidence
    let matches = fusion.combine(evidence);
    println!("\n   Final Results:");
    for (i, m) in matches.iter().enumerate() {
        println!("   {}. {} - {}% confidence", i + 1, m.name, m.accuracy);
    }

    println!("\n=== Example Complete ===");
}
