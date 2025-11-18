use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use nmap_service_detect::SignatureDatabase;

/// Benchmark signature database creation and loading
fn bench_database_creation(c: &mut Criterion) {
    c.bench_function("signature_database_creation", |b| {
        b.iter(|| {
            SignatureDatabase::load_default().unwrap()
        });
    });
}

/// Benchmark tiered loading strategies
fn bench_tiered_loading(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_loading");

    group.bench_function("tier1_only", |b| {
        b.iter(|| {
            SignatureDatabase::load_with_tiers(true, false, false).unwrap()
        });
    });

    group.bench_function("tier1_and_tier2", |b| {
        b.iter(|| {
            SignatureDatabase::load_with_tiers(true, true, false).unwrap()
        });
    });

    group.bench_function("all_tiers", |b| {
        b.iter(|| {
            SignatureDatabase::load_with_tiers(true, true, true).unwrap()
        });
    });

    group.finish();
}

/// Benchmark signature matching performance
fn bench_signature_matching(c: &mut Criterion) {
    let db = SignatureDatabase::load_default().unwrap();

    let test_banners = vec![
        ("apache", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n", 80, "tcp"),
        ("nginx", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n", 80, "tcp"),
        ("ssh", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3", 22, "tcp"),
        ("mysql", "5.7.33-0ubuntu0.18.04.1-MySQL", 3306, "tcp"),
        ("redis", "$256\r\n# Server\r\nredis_version:6.2.5\r\n", 6379, "tcp"),
        ("ftp", "220 (vsFTPd 3.0.3)", 21, "tcp"),
        ("smtp", "220 mail.example.com ESMTP Postfix", 25, "tcp"),
        ("postgres", "PostgreSQL 13.3", 5432, "tcp"),
    ];

    let mut group = c.benchmark_group("banner_matching");

    for (name, banner, port, protocol) in test_banners.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(name), banner, |b, banner| {
            b.iter(|| {
                db.match_banner(black_box(banner), *port, protocol)
            });
        });
    }

    group.finish();
}

/// Benchmark port-based signature lookup
fn bench_port_lookup(c: &mut Criterion) {
    let db = SignatureDatabase::load_default().unwrap();

    let test_ports = vec![
        ("http", 80),
        ("https", 443),
        ("ssh", 22),
        ("ftp", 21),
        ("smtp", 25),
        ("mysql", 3306),
        ("postgres", 5432),
        ("redis", 6379),
    ];

    let mut group = c.benchmark_group("port_lookup");

    for (name, port) in test_ports.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(name), port, |b, port| {
            b.iter(|| {
                db.get_signatures_for_port(black_box(*port))
            });
        });
    }

    group.finish();
}

/// Benchmark service category lookup
fn bench_service_lookup(c: &mut Criterion) {
    let db = SignatureDatabase::load_default().unwrap();

    let test_services = vec!["http", "ssh", "ftp", "smtp", "mysql", "postgresql", "redis"];

    let mut group = c.benchmark_group("service_lookup");

    for service in test_services.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(service), service, |b, service| {
            b.iter(|| {
                db.get_signatures_for_service(black_box(service))
            });
        });
    }

    group.finish();
}

/// Benchmark probe lookup
fn bench_probe_lookup(c: &mut Criterion) {
    let db = SignatureDatabase::load_default().unwrap();

    let test_probes = vec!["NULL", "GetRequest", "SSH", "SMTP", "MySQL", "PostgreSQL"];

    let mut group = c.benchmark_group("probe_lookup");

    for probe in test_probes.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(probe), probe, |b, probe| {
            b.iter(|| {
                db.get_signatures_for_probe(black_box(probe))
            });
        });
    }

    group.finish();
}

/// Benchmark signature count and tier information
fn bench_signature_stats(c: &mut Criterion) {
    let db = SignatureDatabase::load_default().unwrap();

    c.bench_function("get_signature_count", |b| {
        b.iter(|| {
            db.get_signature_count()
        });
    });

    c.bench_function("get_tier_counts", |b| {
        b.iter(|| {
            db.get_tier_counts()
        });
    });

    c.bench_function("get_service_categories", |b| {
        b.iter(|| {
            db.get_service_categories()
        });
    });
}

criterion_group!(
    benches,
    bench_database_creation,
    bench_tiered_loading,
    bench_signature_matching,
    bench_port_lookup,
    bench_service_lookup,
    bench_probe_lookup,
    bench_signature_stats,
);

criterion_main!(benches);
