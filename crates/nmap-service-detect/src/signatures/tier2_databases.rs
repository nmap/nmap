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

    // TimescaleDB (PostgreSQL extension)
    signatures.push(ServiceSignature {
        service_name: "timescaledb".to_string(),
        probe_name: "PostgreSQL".to_string(),
        pattern: r"TimescaleDB.*([0-9]+\.[0-9]+(?:\.[0-9]+)?)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("TimescaleDB".to_string()),
            version: Some("$1".to_string()),
            info: Some("Time-series database on PostgreSQL".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:timescale:timescaledb:$1".to_string()],
        }),
        ports: vec![5432],
        protocol: "tcp".to_string(),
    });

    // ========== DISTRIBUTED DATABASES ==========

    // ClickHouse
    signatures.push(ServiceSignature {
        service_name: "clickhouse".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"ClickHouse.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ClickHouse".to_string()),
            version: Some("$1".to_string()),
            info: Some("OLAP database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:clickhouse:clickhouse:$1".to_string()],
        }),
        ports: vec![9000, 8123],
        protocol: "tcp".to_string(),
    });

    // ScyllaDB (Cassandra-compatible)
    signatures.push(ServiceSignature {
        service_name: "scylladb".to_string(),
        probe_name: "Cassandra".to_string(),
        pattern: r"Scylla.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ScyllaDB".to_string()),
            version: Some("$1".to_string()),
            info: Some("NoSQL database (Cassandra-compatible)".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:scylladb:scylla:$1".to_string()],
        }),
        ports: vec![9042],
        protocol: "tcp".to_string(),
    });

    // CockroachDB
    signatures.push(ServiceSignature {
        service_name: "cockroachdb".to_string(),
        probe_name: "PostgreSQL".to_string(),
        pattern: r"CockroachDB.*v([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("CockroachDB".to_string()),
            version: Some("$1".to_string()),
            info: Some("Distributed SQL database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:cockroach_labs:cockroachdb:$1".to_string()],
        }),
        ports: vec![26257],
        protocol: "tcp".to_string(),
    });

    // YugabyteDB
    signatures.push(ServiceSignature {
        service_name: "yugabytedb".to_string(),
        probe_name: "PostgreSQL".to_string(),
        pattern: r"YugabyteDB.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("YugabyteDB".to_string()),
            version: Some("$1".to_string()),
            info: Some("Distributed SQL database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:yugabyte:yugabytedb:$1".to_string()],
        }),
        ports: vec![7000, 9000],
        protocol: "tcp".to_string(),
    });

    // TiDB
    signatures.push(ServiceSignature {
        service_name: "tidb".to_string(),
        probe_name: "MySQL".to_string(),
        pattern: r"TiDB.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("TiDB".to_string()),
            version: Some("$1".to_string()),
            info: Some("Distributed SQL database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:pingcap:tidb:$1".to_string()],
        }),
        ports: vec![4000],
        protocol: "tcp".to_string(),
    });

    // Vitess
    signatures.push(ServiceSignature {
        service_name: "vitess".to_string(),
        probe_name: "MySQL".to_string(),
        pattern: r"Vitess.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Vitess".to_string()),
            version: Some("$1".to_string()),
            info: Some("MySQL sharding middleware".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:vitess:vitess:$1".to_string()],
        }),
        ports: vec![15991, 15999],
        protocol: "tcp".to_string(),
    });

    // ========== MULTI-MODEL DATABASES ==========

    // ArangoDB
    signatures.push(ServiceSignature {
        service_name: "arangodb".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""server":"arango".*"version":"([0-9.]+)""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("ArangoDB".to_string()),
            version: Some("$1".to_string()),
            info: Some("Multi-model database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:arangodb:arangodb:$1".to_string()],
        }),
        ports: vec![8529],
        protocol: "tcp".to_string(),
    });

    // OrientDB
    signatures.push(ServiceSignature {
        service_name: "orientdb".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"OrientDB.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OrientDB".to_string()),
            version: Some("$1".to_string()),
            info: Some("Multi-model database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:orientdb:orientdb:$1".to_string()],
        }),
        ports: vec![2424, 2480],
        protocol: "tcp".to_string(),
    });

    // Couchbase
    signatures.push(ServiceSignature {
        service_name: "couchbase".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"([0-9.]+)".*Couchbase"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Couchbase Server".to_string()),
            version: Some("$1".to_string()),
            info: Some("NoSQL document database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:couchbase:couchbase_server:$1".to_string()],
        }),
        ports: vec![8091, 8092, 8093, 8094, 8095, 8096],
        protocol: "tcp".to_string(),
    });

    // SurrealDB
    signatures.push(ServiceSignature {
        service_name: "surrealdb".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"SurrealDB.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SurrealDB".to_string()),
            version: Some("$1".to_string()),
            info: Some("Multi-model database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:surrealdb:surrealdb:$1".to_string()],
        }),
        ports: vec![8000],
        protocol: "tcp".to_string(),
    });

    // ========== GRAPH DATABASES ==========

    // Dgraph
    signatures.push(ServiceSignature {
        service_name: "dgraph".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"v([0-9.]+)".*dgraph"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Dgraph".to_string()),
            version: Some("$1".to_string()),
            info: Some("Graph database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:dgraph:dgraph:$1".to_string()],
        }),
        ports: vec![8080, 9080],
        protocol: "tcp".to_string(),
    });

    // ========== CLOUD-NATIVE & TESTING DATABASES ==========

    // DynamoDB Local
    signatures.push(ServiceSignature {
        service_name: "dynamodb-local".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"DynamoDB Local|X-Amzn-RequestId".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Amazon DynamoDB Local".to_string()),
            version: None,
            info: Some("Local testing version".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:amazon:dynamodb_local".to_string()],
        }),
        ports: vec![8000],
        protocol: "tcp".to_string(),
    });

    // FaunaDB
    signatures.push(ServiceSignature {
        service_name: "faunadb".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Fauna".to_string(),
        version_info: Some(VersionInfo {
            product: Some("FaunaDB".to_string()),
            version: None,
            info: Some("Distributed document-relational database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:fauna:faunadb".to_string()],
        }),
        ports: vec![8443],
        protocol: "tcp".to_string(),
    });

    // Firestore Emulator
    signatures.push(ServiceSignature {
        service_name: "firestore".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Cloud Firestore Emulator".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Google Cloud Firestore Emulator".to_string()),
            version: None,
            info: Some("NoSQL document database emulator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:google:cloud_firestore".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    signatures
}
