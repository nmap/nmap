/// Performance Benchmarks for R-Map
/// Comparison with nmap and performance regression testing

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

// Import functions to benchmark
// Note: These would normally be in a lib.rs that both main.rs and benches use

/// Benchmark: Hostname validation performance
fn benchmark_hostname_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hostname_validation");

    // Test cases
    let valid_hostnames = vec![
        "example.com",
        "subdomain.example.com",
        "deep.subdomain.example.com",
        "test-123.example.co.uk",
    ];

    let long_hostname = "a".repeat(300);
    let invalid_hostnames = vec![
        "example.com;whoami",
        "example.com|ls",
        "../../../etc/passwd",
        long_hostname.as_str(), // Too long
    ];

    // Benchmark valid hostname validation
    for hostname in &valid_hostnames {
        group.bench_with_input(
            BenchmarkId::new("valid", hostname),
            hostname,
            |b, h| {
                b.iter(|| {
                    validate_hostname_bench(black_box(h))
                });
            },
        );
    }

    // Benchmark invalid hostname rejection
    for hostname in &invalid_hostnames {
        let name = if hostname.len() > 30 {
            "long_hostname"
        } else {
            hostname
        };
        group.bench_with_input(
            BenchmarkId::new("invalid", name),
            hostname,
            |b, h| {
                b.iter(|| {
                    validate_hostname_bench(black_box(h))
                });
            },
        );
    }

    // Throughput benchmark: 10k validations
    group.throughput(Throughput::Elements(10000));
    group.bench_function("throughput_10k", |b| {
        b.iter(|| {
            for _ in 0..10000 {
                validate_hostname_bench(black_box("example.com"));
            }
        });
    });

    group.finish();
}

/// Benchmark: IP address validation (SSRF protection)
fn benchmark_ip_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ip_validation");

    let test_ips = vec![
        ("public_ipv4", IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ("private_ipv4_10", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        ("private_ipv4_192", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        ("metadata", IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
        ("loopback_ipv4", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        ("public_ipv6", IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888))),
        ("loopback_ipv6", IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ];

    for (name, ip) in &test_ips {
        group.bench_with_input(
            BenchmarkId::new("ssrf_check", name),
            ip,
            |b, ip_addr| {
                b.iter(|| {
                    is_private_ip_bench(black_box(*ip_addr));
                    is_cloud_metadata_endpoint_bench(black_box(*ip_addr));
                });
            },
        );
    }

    // Throughput benchmark
    group.throughput(Throughput::Elements(100000));
    group.bench_function("throughput_100k", |b| {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        b.iter(|| {
            for _ in 0..100000 {
                is_private_ip_bench(black_box(ip));
            }
        });
    });

    group.finish();
}

/// Benchmark: Banner sanitization performance
fn benchmark_banner_sanitization(c: &mut Criterion) {
    let mut group = c.benchmark_group("banner_sanitization");

    let long_banner = "A".repeat(1024);
    let test_banners = vec![
        ("clean", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"),
        ("ansi_codes", "\x1b[31mSSH-2.0-Server\x1b[0m"),
        ("control_chars", "SSH-2.0\x00\x07\x1b-Server"),
        ("long_banner", long_banner.as_str()),
        ("mixed", "\x1b[1;31mHTTP/1.1\x00200 OK\x07\x1b[0m"),
    ];

    for (name, banner) in &test_banners {
        group.bench_with_input(
            BenchmarkId::new("sanitize", name),
            banner,
            |b, text| {
                b.iter(|| {
                    sanitize_banner_bench(black_box(text))
                });
            },
        );
    }

    // Throughput benchmark
    group.throughput(Throughput::Elements(10000));
    group.bench_function("throughput_10k", |b| {
        let banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
        b.iter(|| {
            for _ in 0..10000 {
                sanitize_banner_bench(black_box(banner));
            }
        });
    });

    group.finish();
}

/// Benchmark: Path validation performance
fn benchmark_path_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_validation");

    let long_path = "/tmp/".repeat(100);
    let test_paths = vec![
        ("normal", "/tmp/scan-results.json"),
        ("traversal", "../../../etc/passwd"),
        ("windows", "C:\\Windows\\System32\\config\\sam"),
        ("long_path", long_path.as_str()),
        ("null_byte", "/tmp/output\0.json"),
    ];

    for (name, path) in &test_paths {
        group.bench_with_input(
            BenchmarkId::new("validate", name),
            path,
            |b, p| {
                b.iter(|| {
                    validate_path_bench(black_box(p))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Port parsing and validation
fn benchmark_port_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_parsing");

    let test_specs = vec![
        ("single", "80"),
        ("range", "1-1000"),
        ("list", "22,80,443,8080"),
        ("complex", "1-100,443,8000-9000"),
        ("top_ports", "1-65535"),
    ];

    for (name, spec) in &test_specs {
        group.bench_with_input(
            BenchmarkId::new("parse", name),
            spec,
            |b, s| {
                b.iter(|| {
                    parse_port_spec_bench(black_box(s))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: CIDR parsing and host enumeration
fn benchmark_cidr_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("cidr_parsing");

    let test_cidrs = vec![
        ("/32", "8.8.8.8/32"),      // Single host
        ("/24", "192.168.1.0/24"),  // 254 hosts
        ("/16", "10.0.0.0/16"),     // 65534 hosts (limited to 1000)
    ];

    for (name, cidr) in &test_cidrs {
        group.bench_with_input(
            BenchmarkId::new("parse", name),
            cidr,
            |b, c| {
                b.iter(|| {
                    parse_cidr_bench(black_box(c))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Concurrent connection simulation
fn benchmark_concurrent_connections(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_connections");
    group.sample_size(10); // Fewer samples for expensive benchmarks
    group.measurement_time(Duration::from_secs(30));

    // Simulate semaphore acquisition/release
    let connection_counts = vec![10, 50, 100, 200];

    for count in connection_counts {
        group.bench_with_input(
            BenchmarkId::new("semaphore", count),
            &count,
            |b, &cnt| {
                b.iter(|| {
                    simulate_concurrent_connections_bench(black_box(cnt))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Memory allocation patterns
fn benchmark_memory_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_allocation");

    // Benchmark Vec allocation for results
    let result_counts = vec![10, 100, 1000, 10000];

    for count in result_counts {
        group.bench_with_input(
            BenchmarkId::new("vec_allocation", count),
            &count,
            |b, &cnt| {
                b.iter(|| {
                    allocate_results_bench(black_box(cnt))
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Helper functions (implementations would come from lib.rs)
// ============================================================================

fn validate_hostname_bench(hostname: &str) -> bool {
    const MAX_HOSTNAME_LENGTH: usize = 253;
    const MAX_LABEL_LENGTH: usize = 63;

    if hostname.is_empty() || hostname.len() > MAX_HOSTNAME_LENGTH {
        return false;
    }

    if hostname.starts_with('-') || hostname.starts_with('.') ||
       hostname.ends_with('-') || hostname.ends_with('.') {
        return false;
    }

    let labels: Vec<&str> = hostname.split('.').collect();

    for label in labels {
        if label.is_empty() || label.len() > MAX_LABEL_LENGTH {
            return false;
        }

        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }

        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                return false;
            }
        }
    }

    // Check for suspicious characters
    let suspicious_chars = ['\\', '/', '|', '&', ';', '`', '$', '(', ')', '\0'];
    for &ch in &suspicious_chars {
        if hostname.contains(ch) {
            return false;
        }
    }

    true
}

fn is_private_ip_bench(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 10 ||
            (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
            (octets[0] == 192 && octets[1] == 168) ||
            octets[0] == 127 ||
            (octets[0] == 169 && octets[1] == 254) ||
            octets[0] >= 224 && octets[0] <= 239
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_multicast() ||
            (ipv6.segments()[0] & 0xffc0) == 0xfe80 ||
            (ipv6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn is_cloud_metadata_endpoint_bench(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4 == Ipv4Addr::new(169, 254, 169, 254),
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            segments[0] == 0xfd00 && segments[1] == 0xec2 && segments[7] == 0x254
        }
    }
}

fn sanitize_banner_bench(banner: &str) -> String {
    const MAX_BANNER_LENGTH: usize = 512;
    let truncated = if banner.len() > MAX_BANNER_LENGTH {
        &banner[..MAX_BANNER_LENGTH]
    } else {
        banner
    };

    let mut result = String::with_capacity(truncated.len());
    for ch in truncated.chars() {
        if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
            result.push('.');
        } else {
            result.push(ch);
        }
    }

    result.replace("\x1b", "")
}

fn validate_path_bench(path: &str) -> bool {
    if path.contains('\0') || path.contains('\n') {
        return false;
    }

    if path.contains("..") {
        return false;
    }

    if path.len() > 4096 {
        return false;
    }

    let path_lower = path.to_lowercase();
    if path_lower.starts_with("/etc/") || path_lower.starts_with("/sys/") ||
       path_lower.starts_with("/proc/") || path_lower.contains("c:\\windows\\") {
        return false;
    }

    true
}

fn parse_port_spec_bench(spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u16>(), end.parse::<u16>()) {
                for port in s..=e.min(65535) {
                    ports.push(port);
                    if ports.len() >= 1000 {
                        return ports;
                    }
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        }
    }

    ports
}

fn parse_cidr_bench(cidr: &str) -> Vec<IpAddr> {
    // Simplified CIDR parsing for benchmark
    let mut hosts = Vec::new();

    if let Ok(network) = cidr.parse::<ipnet::IpNet>() {
        for ip in network.hosts().take(1000) {
            hosts.push(ip);
        }
    }

    hosts
}

fn simulate_concurrent_connections_bench(count: usize) {
    // Simulate semaphore-based connection limiting
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let semaphore = Arc::new(Semaphore::new(100));
        let mut handles = Vec::new();

        for _ in 0..count {
            let sem = semaphore.clone();
            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                // Simulate work
                tokio::time::sleep(Duration::from_micros(10)).await;
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }
    });
}

fn allocate_results_bench(count: usize) -> Vec<(u16, String)> {
    let mut results = Vec::with_capacity(count);
    for i in 0..count {
        results.push((i as u16, format!("Port {} open", i)));
    }
    results
}

// ============================================================================
// Criterion configuration
// ============================================================================

criterion_group!(
    benches,
    benchmark_hostname_validation,
    benchmark_ip_validation,
    benchmark_banner_sanitization,
    benchmark_path_validation,
    benchmark_port_parsing,
    benchmark_cidr_parsing,
    benchmark_concurrent_connections,
    benchmark_memory_allocation
);

criterion_main!(benches);
