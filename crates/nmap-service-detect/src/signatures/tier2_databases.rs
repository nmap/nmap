use crate::signatures::{ServiceSignature, VersionInfo};

/// Tier 2 Databases - Database server signatures
/// Covers SQL, NoSQL, and specialized data stores
pub fn load_tier2_database_signatures() -> Vec<ServiceSignature> {
    let mut signatures = Vec::new();

    // ========== RELATIONAL DATABASES ==========

    // MySQL
    signatures.push(ServiceSignature {
        service_name: "mysql".to_string(),
        probe_name: "MySQL".to_string(),
        pattern: r"([0-9.]+)-MariaDB|([0-9.]+).*MySQL".to_string(),
        version_info: Some(VersionInfo {
            product: Some("MySQL".to_string()),
            version: Some("$1$2".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mysql:mysql:$1$2".to_string()],
        }),
        ports: vec![3306],
        protocol: "tcp".to_string(),
    });

    // MariaDB
    signatures.push(ServiceSignature {
        service_name: "mysql".to_string(),
        probe_name: "MySQL".to_string(),
        pattern: r"([0-9.]+)-MariaDB".to_string(),
        version_info: Some(VersionInfo {
            product: Some("MariaDB".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mariadb:mariadb:$1".to_string()],
        }),
        ports: vec![3306],
        protocol: "tcp".to_string(),
    });

    // PostgreSQL
    signatures.push(ServiceSignature {
        service_name: "postgresql".to_string(),
        probe_name: "PostgreSQL".to_string(),
        pattern: r"PostgreSQL.*([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("PostgreSQL".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:postgresql:postgresql:$1".to_string()],
        }),
        ports: vec![5432],
        protocol: "tcp".to_string(),
    });

    // Oracle Database
    signatures.push(ServiceSignature {
        service_name: "oracle".to_string(),
        probe_name: "Oracle".to_string(),
        pattern: r"Oracle.*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Oracle Database".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:oracle:database_server:$1".to_string()],
        }),
        ports: vec![1521, 1526],
        protocol: "tcp".to_string(),
    });

    // Microsoft SQL Server
    signatures.push(ServiceSignature {
        service_name: "mssql".to_string(),
        probe_name: "MSSQL".to_string(),
        pattern: r"Microsoft SQL Server.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Microsoft SQL Server".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: Some("Windows".to_string()),
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:sql_server:$1".to_string()],
        }),
        ports: vec![1433, 1434],
        protocol: "tcp".to_string(),
    });

    // SQLite (network exposed via various means)
    signatures.push(ServiceSignature {
        service_name: "sqlite".to_string(),
        probe_name: "SQLite".to_string(),
        pattern: r"SQLite.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SQLite".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:sqlite:sqlite:$1".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // ========== NOSQL DATABASES ==========

    // MongoDB
    signatures.push(ServiceSignature {
        service_name: "mongodb".to_string(),
        probe_name: "MongoDB".to_string(),
        pattern: r"MongoDB.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("MongoDB".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mongodb:mongodb:$1".to_string()],
        }),
        ports: vec![27017, 27018, 27019],
        protocol: "tcp".to_string(),
    });

    // Redis
    signatures.push(ServiceSignature {
        service_name: "redis".to_string(),
        probe_name: "Redis".to_string(),
        pattern: r"\$[0-9]+\r\n[\s\S]*redis_version:([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Redis".to_string()),
            version: Some("$1".to_string()),
            info: Some("key-value store".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:redis:redis:$1".to_string()],
        }),
        ports: vec![6379],
        protocol: "tcp".to_string(),
    });

    // Memcached
    signatures.push(ServiceSignature {
        service_name: "memcached".to_string(),
        probe_name: "Memcached".to_string(),
        pattern: r"VERSION ([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Memcached".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:memcached:memcached:$1".to_string()],
        }),
        ports: vec![11211],
        protocol: "tcp".to_string(),
    });

    // CouchDB
    signatures.push(ServiceSignature {
        service_name: "couchdb".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""couchdb":"Welcome".*"version":"([0-9.]+)""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache CouchDB".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:couchdb:$1".to_string()],
        }),
        ports: vec![5984],
        protocol: "tcp".to_string(),
    });

    // Apache Cassandra
    signatures.push(ServiceSignature {
        service_name: "cassandra".to_string(),
        probe_name: "Cassandra".to_string(),
        pattern: r"Cassandra.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache Cassandra".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:cassandra:$1".to_string()],
        }),
        ports: vec![9042, 9160],
        protocol: "tcp".to_string(),
    });

    // Neo4j
    signatures.push(ServiceSignature {
        service_name: "neo4j".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""neo4j_version"\s*:\s*"([0-9.]+)""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Neo4j".to_string()),
            version: Some("$1".to_string()),
            info: Some("Graph database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:neo4j:neo4j:$1".to_string()],
        }),
        ports: vec![7474, 7687],
        protocol: "tcp".to_string(),
    });

    // RethinkDB
    signatures.push(ServiceSignature {
        service_name: "rethinkdb".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"RethinkDB.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("RethinkDB".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:rethinkdb:rethinkdb:$1".to_string()],
        }),
        ports: vec![28015, 29015, 8080],
        protocol: "tcp".to_string(),
    });

    // ========== SEARCH & ANALYTICS ==========

    // Elasticsearch
    signatures.push(ServiceSignature {
        service_name: "elasticsearch".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version"\s*:\s*\{\s*"number"\s*:\s*"([0-9.]+)""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Elasticsearch".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:elasticsearch:elasticsearch:$1".to_string()],
        }),
        ports: vec![9200, 9300],
        protocol: "tcp".to_string(),
    });

    // Elasticsearch (alternative pattern)
    signatures.push(ServiceSignature {
        service_name: "elasticsearch".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""name"\s*:\s*"[^"]+",\s*"cluster_name""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Elasticsearch".to_string()),
            version: None,
            info: Some("Search engine".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:elasticsearch:elasticsearch".to_string()],
        }),
        ports: vec![9200],
        protocol: "tcp".to_string(),
    });

    // ========== TIME SERIES DATABASES ==========

    // InfluxDB
    signatures.push(ServiceSignature {
        service_name: "influxdb".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"X-Influxdb-Version: ([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("InfluxDB".to_string()),
            version: Some("$1".to_string()),
            info: Some("Time series database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:influxdata:influxdb:$1".to_string()],
        }),
        ports: vec![8086],
        protocol: "tcp".to_string(),
    });

    // InfluxDB (alternative pattern)
    signatures.push(ServiceSignature {
        service_name: "influxdb".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"influxdb".to_string(),
        version_info: Some(VersionInfo {
            product: Some("InfluxDB".to_string()),
            version: None,
            info: Some("Time series database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:influxdata:influxdb".to_string()],
        }),
        ports: vec![8086, 8088],
        protocol: "tcp".to_string(),
    });

    signatures
}
