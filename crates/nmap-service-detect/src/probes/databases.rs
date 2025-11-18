use crate::probes::Probe;

/// Load database-specific probes
/// These probes are used to detect various database services
pub fn load_database_probes() -> Vec<Probe> {
    let mut probes = Vec::new();

    // MySQL probe
    probes.push(Probe {
        name: "MySQL".to_string(),
        protocol: "tcp".to_string(),
        data: vec![],  // MySQL servers send handshake on connect
        ports: vec![3306],
        ssl_ports: vec![],
        rarity: 5,
        fallback: Some("NULL".to_string()),
    });

    // PostgreSQL probe
    probes.push(Probe {
        name: "PostgreSQL".to_string(),
        protocol: "tcp".to_string(),
        data: vec![
            0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f,
        ],
        ports: vec![5432],
        ssl_ports: vec![],
        rarity: 5,
        fallback: Some("NULL".to_string()),
    });

    // MongoDB probe (using ismaster command)
    probes.push(Probe {
        name: "MongoDB".to_string(),
        protocol: "tcp".to_string(),
        data: vec![],  // MongoDB Wire Protocol - would need proper OP_QUERY packet
        ports: vec![27017, 27018, 27019],
        ssl_ports: vec![],
        rarity: 5,
        fallback: Some("NULL".to_string()),
    });

    // Redis probe
    probes.push(Probe {
        name: "Redis".to_string(),
        protocol: "tcp".to_string(),
        data: b"INFO\r\n".to_vec(),
        ports: vec![6379],
        ssl_ports: vec![],
        rarity: 5,
        fallback: Some("NULL".to_string()),
    });

    // Memcached probe
    probes.push(Probe {
        name: "Memcached".to_string(),
        protocol: "tcp".to_string(),
        data: b"version\r\n".to_vec(),
        ports: vec![11211],
        ssl_ports: vec![],
        rarity: 5,
        fallback: Some("NULL".to_string()),
    });

    // MSSQL probe (TDS protocol)
    probes.push(Probe {
        name: "MSSQL".to_string(),
        protocol: "tcp".to_string(),
        data: vec![
            0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
        ],
        ports: vec![1433, 1434],
        ssl_ports: vec![],
        rarity: 5,
        fallback: Some("NULL".to_string()),
    });

    // Oracle probe (TNS protocol)
    probes.push(Probe {
        name: "Oracle".to_string(),
        protocol: "tcp".to_string(),
        data: vec![
            0x00, 0x3a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
        ],
        ports: vec![1521, 1526],
        ssl_ports: vec![],
        rarity: 5,
        fallback: Some("NULL".to_string()),
    });

    // Cassandra probe (CQL native protocol)
    probes.push(Probe {
        name: "Cassandra".to_string(),
        protocol: "tcp".to_string(),
        data: vec![0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        ports: vec![9042, 9160],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // SQLite probe (not typically networked, but included for completeness)
    probes.push(Probe {
        name: "SQLite".to_string(),
        protocol: "tcp".to_string(),
        data: vec![],
        ports: vec![],
        ssl_ports: vec![],
        rarity: 9,
        fallback: Some("NULL".to_string()),
    });

    probes
}

/// Load message queue probes
/// For services like RabbitMQ, Kafka, MQTT, etc.
pub fn load_message_queue_probes() -> Vec<Probe> {
    let mut probes = Vec::new();

    // AMQP probe (RabbitMQ)
    probes.push(Probe {
        name: "AMQP".to_string(),
        protocol: "tcp".to_string(),
        data: b"AMQP\x00\x00\x09\x01".to_vec(),
        ports: vec![5672, 5671],
        ssl_ports: vec![5671],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // Kafka probe (would need proper Kafka protocol)
    probes.push(Probe {
        name: "Kafka".to_string(),
        protocol: "tcp".to_string(),
        data: vec![],  // Kafka Protocol - complex binary protocol
        ports: vec![9092],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // MQTT probe
    probes.push(Probe {
        name: "MQTT".to_string(),
        protocol: "tcp".to_string(),
        data: vec![
            0x10, 0x0c, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
            0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
        ],
        ports: vec![1883],
        ssl_ports: vec![8883],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // NATS probe
    probes.push(Probe {
        name: "NATS".to_string(),
        protocol: "tcp".to_string(),
        data: vec![],  // NATS sends INFO on connect
        ports: vec![4222, 6222, 8222],
        ssl_ports: vec![],
        rarity: 6,
        fallback: Some("NULL".to_string()),
    });

    // ZeroMQ probe
    probes.push(Probe {
        name: "ZeroMQ".to_string(),
        protocol: "tcp".to_string(),
        data: vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f],
        ports: vec![],
        ssl_ports: vec![],
        rarity: 7,
        fallback: Some("NULL".to_string()),
    });

    // Pulsar probe
    probes.push(Probe {
        name: "Pulsar".to_string(),
        protocol: "tcp".to_string(),
        data: vec![],  // Pulsar binary protocol
        ports: vec![6650, 6651],
        ssl_ports: vec![6651],
        rarity: 7,
        fallback: Some("NULL".to_string()),
    });

    probes
}
