use crate::{OsMatch, OsClass};
use nmap_core::{NmapError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintEntry {
    pub fingerprint: String,
    pub os_matches: Vec<OsMatch>,
}

pub struct FingerprintDatabase {
    entries: Vec<FingerprintEntry>,
    index: HashMap<String, Vec<usize>>,
}

impl FingerprintDatabase {
    pub fn load_default() -> Result<Self> {
        // In a real implementation, this would load from nmap-os-db
        // For now, we'll create a minimal database with common OS signatures
        let entries = vec![
            FingerprintEntry {
                fingerprint: "SEQ(SP=100,GCD=1,ISR=10A,TI=Z,CI=I,II=I,TS=A)".to_string(),
                os_matches: vec![
                    OsMatch {
                        name: "Linux 2.6.X".to_string(),
                        accuracy: 95,
                        line: "Linux 2.6.9 - 2.6.33".to_string(),
                        os_class: vec![
                            OsClass {
                                vendor: "Linux".to_string(),
                                os_gen: "2.6.X".to_string(),
                                os_type: "general purpose".to_string(),
                                accuracy: 95,
                                cpe: vec!["cpe:/o:linux:linux_kernel:2.6".to_string()],
                            }
                        ],
                    }
                ],
            },
            FingerprintEntry {
                fingerprint: "SEQ(SP=FF,GCD=1,ISR=10B,TI=RD,CI=I,II=I,TS=A)".to_string(),
                os_matches: vec![
                    OsMatch {
                        name: "Microsoft Windows".to_string(),
                        accuracy: 90,
                        line: "Microsoft Windows 7|8|10".to_string(),
                        os_class: vec![
                            OsClass {
                                vendor: "Microsoft".to_string(),
                                os_gen: "Windows".to_string(),
                                os_type: "general purpose".to_string(),
                                accuracy: 90,
                                cpe: vec!["cpe:/o:microsoft:windows".to_string()],
                            }
                        ],
                    }
                ],
            },
            FingerprintEntry {
                fingerprint: "SEQ(SP=0,GCD=1,ISR=10C,TI=Z,CI=I,II=I,TS=U)".to_string(),
                os_matches: vec![
                    OsMatch {
                        name: "FreeBSD".to_string(),
                        accuracy: 88,
                        line: "FreeBSD 8.0 - 12.0".to_string(),
                        os_class: vec![
                            OsClass {
                                vendor: "FreeBSD".to_string(),
                                os_gen: "FreeBSD".to_string(),
                                os_type: "general purpose".to_string(),
                                accuracy: 88,
                                cpe: vec!["cpe:/o:freebsd:freebsd".to_string()],
                            }
                        ],
                    }
                ],
            },
        ];

        let mut index = HashMap::new();
        for (i, entry) in entries.iter().enumerate() {
            // Simple indexing by first few characters of fingerprint
            let key = entry.fingerprint.chars().take(10).collect::<String>();
            index.entry(key).or_insert_with(Vec::new).push(i);
        }

        Ok(Self { entries, index })
    }

    pub fn match_fingerprint(&self, fingerprint: &str) -> Result<Vec<OsMatch>> {
        let mut matches = Vec::new();
        let mut best_score = 0;

        for entry in &self.entries {
            let score = self.calculate_similarity(fingerprint, &entry.fingerprint);
            if score > 70 { // Minimum similarity threshold
                for mut os_match in entry.os_matches.clone() {
                    os_match.accuracy = ((score as f32 * os_match.accuracy as f32) / 100.0) as u8;
                    matches.push(os_match);
                }
                if score > best_score {
                    best_score = score;
                }
            }
        }

        // Sort by accuracy
        matches.sort_by(|a, b| b.accuracy.cmp(&a.accuracy));
        
        // Limit to top 5 matches
        matches.truncate(5);

        Ok(matches)
    }

    fn calculate_similarity(&self, fp1: &str, fp2: &str) -> u8 {
        // Simple similarity calculation based on common substrings
        // In a real implementation, this would be much more sophisticated
        let lines1: Vec<&str> = fp1.lines().collect();
        let lines2: Vec<&str> = fp2.lines().collect();
        
        let mut matches = 0;
        let mut total = 0;

        for line1 in &lines1 {
            total += 1;
            if lines2.iter().any(|line2| self.lines_similar(line1, line2)) {
                matches += 1;
            }
        }

        if total == 0 {
            return 0;
        }

        ((matches as f32 / total as f32) * 100.0) as u8
    }

    fn lines_similar(&self, line1: &str, line2: &str) -> bool {
        // Extract test type (e.g., "SEQ", "WIN", "T1")
        let test1 = line1.split('(').next().unwrap_or("");
        let test2 = line2.split('(').next().unwrap_or("");
        
        if test1 != test2 {
            return false;
        }

        // For now, just check if test types match
        // Real implementation would parse and compare individual attributes
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_database_creation() {
        let db = FingerprintDatabase::load_default().unwrap();
        assert!(!db.entries.is_empty());
    }

    #[test]
    fn test_fingerprint_matching() {
        let db = FingerprintDatabase::load_default().unwrap();
        let test_fp = "SEQ(SP=100,GCD=1,ISR=10A,TI=Z,CI=I,II=I,TS=A)";
        let matches = db.match_fingerprint(test_fp).unwrap();
        assert!(!matches.is_empty());
    }
}