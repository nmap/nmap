use crate::signatures::{ServiceSignature, VersionInfo};

/// Tier 2 Message Queues - Message broker and queue system signatures
/// Covers enterprise message queues, cloud messaging, and streaming platforms
pub fn load_tier2_queue_signatures() -> Vec<ServiceSignature> {
    let mut signatures = Vec::new();

    // ========== APACHE KAFKA ==========

    // Apache Kafka - Main broker
    signatures.push(ServiceSignature {
        service_name: "kafka".to_string(),
        probe_name: "Kafka".to_string(),
        pattern: r"kafka\.common\.protocol.*version".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache Kafka".to_string()),
            version: None,
            info: Some("Distributed streaming platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:kafka".to_string()],
        }),
        ports: vec![9092, 9093],
        protocol: "tcp".to_string(),
    });

    // Kafka Connect
    signatures.push(ServiceSignature {
        service_name: "kafka-connect".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"([0-9.]+)".*kafka.*connect"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kafka Connect".to_string()),
            version: Some("$1".to_string()),
            info: Some("Streaming data integration".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:kafka_connect:$1".to_string()],
        }),
        ports: vec![8083],
        protocol: "tcp".to_string(),
    });

    // Kafka Schema Registry
    signatures.push(ServiceSignature {
        service_name: "kafka-schema-registry".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"schema-registry".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Confluent Schema Registry".to_string()),
            version: None,
            info: Some("Kafka schema management".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:confluent:schema_registry".to_string()],
        }),
        ports: vec![8081],
        protocol: "tcp".to_string(),
    });

    // Kafka REST Proxy
    signatures.push(ServiceSignature {
        service_name: "kafka-rest-proxy".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"kafka-rest".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Confluent REST Proxy".to_string()),
            version: None,
            info: Some("HTTP interface to Kafka".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:confluent:kafka_rest_proxy".to_string()],
        }),
        ports: vec![8082],
        protocol: "tcp".to_string(),
    });

    // Confluent Control Center
    signatures.push(ServiceSignature {
        service_name: "confluent-control-center".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Confluent Control Center".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Confluent Control Center".to_string()),
            version: None,
            info: Some("Kafka cluster management UI".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:confluent:control_center".to_string()],
        }),
        ports: vec![9021],
        protocol: "tcp".to_string(),
    });

    // ========== RABBITMQ ==========

    // RabbitMQ - AMQP
    signatures.push(ServiceSignature {
        service_name: "rabbitmq".to_string(),
        probe_name: "AMQP".to_string(),
        pattern: r"AMQP.*RabbitMQ.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("RabbitMQ".to_string()),
            version: Some("$1".to_string()),
            info: Some("AMQP message broker".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:vmware:rabbitmq:$1".to_string()],
        }),
        ports: vec![5672, 5671],
        protocol: "tcp".to_string(),
    });

    // RabbitMQ Management UI
    signatures.push(ServiceSignature {
        service_name: "rabbitmq-management".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""rabbitmq_version":"([0-9.]+)""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("RabbitMQ Management".to_string()),
            version: Some("$1".to_string()),
            info: Some("Management UI".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:vmware:rabbitmq:$1".to_string()],
        }),
        ports: vec![15672, 15671],
        protocol: "tcp".to_string(),
    });

    // RabbitMQ Stream
    signatures.push(ServiceSignature {
        service_name: "rabbitmq-stream".to_string(),
        probe_name: "RabbitMQStream".to_string(),
        pattern: r"rabbitmq_stream".to_string(),
        version_info: Some(VersionInfo {
            product: Some("RabbitMQ Streams".to_string()),
            version: None,
            info: Some("High-throughput persistent messaging".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:vmware:rabbitmq".to_string()],
        }),
        ports: vec![5552],
        protocol: "tcp".to_string(),
    });

    // ========== NATS ==========

    // NATS Server
    signatures.push(ServiceSignature {
        service_name: "nats".to_string(),
        probe_name: "NATS".to_string(),
        pattern: r#"INFO.*"server_name":"nats-server".*"version":"([0-9.]+)""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("NATS Server".to_string()),
            version: Some("$1".to_string()),
            info: Some("Cloud native messaging system".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nats:nats-server:$1".to_string()],
        }),
        ports: vec![4222],
        protocol: "tcp".to_string(),
    });

    // NATS Streaming (deprecated but still in use)
    signatures.push(ServiceSignature {
        service_name: "nats-streaming".to_string(),
        probe_name: "NATS".to_string(),
        pattern: r"nats-streaming".to_string(),
        version_info: Some(VersionInfo {
            product: Some("NATS Streaming".to_string()),
            version: None,
            info: Some("Persistent messaging on NATS".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nats:nats-streaming".to_string()],
        }),
        ports: vec![4223],
        protocol: "tcp".to_string(),
    });

    // NATS Monitoring
    signatures.push(ServiceSignature {
        service_name: "nats-monitoring".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""server_id":".*"version":"([0-9.]+)".*nats"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("NATS Monitoring".to_string()),
            version: Some("$1".to_string()),
            info: Some("NATS server metrics".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nats:nats-server:$1".to_string()],
        }),
        ports: vec![8222],
        protocol: "tcp".to_string(),
    });

    // NATS Cluster
    signatures.push(ServiceSignature {
        service_name: "nats-cluster".to_string(),
        probe_name: "NATS".to_string(),
        pattern: r"cluster".to_string(),
        version_info: Some(VersionInfo {
            product: Some("NATS Cluster".to_string()),
            version: None,
            info: Some("NATS cluster routing".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nats:nats-server".to_string()],
        }),
        ports: vec![6222],
        protocol: "tcp".to_string(),
    });

    // ========== APACHE PULSAR ==========

    // Apache Pulsar Broker
    signatures.push(ServiceSignature {
        service_name: "pulsar".to_string(),
        probe_name: "Pulsar".to_string(),
        pattern: r"Apache Pulsar.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache Pulsar".to_string()),
            version: Some("$1".to_string()),
            info: Some("Distributed pub-sub messaging".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:pulsar:$1".to_string()],
        }),
        ports: vec![6650, 6651],
        protocol: "tcp".to_string(),
    });

    // Pulsar Admin API
    signatures.push(ServiceSignature {
        service_name: "pulsar-admin".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"pulsar.*admin".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache Pulsar Admin API".to_string()),
            version: None,
            info: Some("Pulsar administration interface".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:pulsar".to_string()],
        }),
        ports: vec![8080, 8443],
        protocol: "tcp".to_string(),
    });

    // Pulsar Proxy
    signatures.push(ServiceSignature {
        service_name: "pulsar-proxy".to_string(),
        probe_name: "Pulsar".to_string(),
        pattern: r"pulsar.*proxy".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache Pulsar Proxy".to_string()),
            version: None,
            info: Some("Pulsar protocol proxy".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:pulsar".to_string()],
        }),
        ports: vec![6650],
        protocol: "tcp".to_string(),
    });

    // ========== ACTIVEMQ ==========

    // ActiveMQ Classic
    signatures.push(ServiceSignature {
        service_name: "activemq".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"ActiveMQ.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache ActiveMQ Classic".to_string()),
            version: Some("$1".to_string()),
            info: Some("JMS message broker".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:activemq:$1".to_string()],
        }),
        ports: vec![61616],
        protocol: "tcp".to_string(),
    });

    // ActiveMQ Artemis
    signatures.push(ServiceSignature {
        service_name: "activemq-artemis".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"ActiveMQ Artemis.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache ActiveMQ Artemis".to_string()),
            version: Some("$1".to_string()),
            info: Some("Next-gen ActiveMQ broker".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:activemq_artemis:$1".to_string()],
        }),
        ports: vec![61616, 5445, 5672],
        protocol: "tcp".to_string(),
    });

    // ActiveMQ Web Console
    signatures.push(ServiceSignature {
        service_name: "activemq-console".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Apache ActiveMQ.*admin".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ActiveMQ Web Console".to_string()),
            version: None,
            info: Some("Management interface".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:activemq".to_string()],
        }),
        ports: vec![8161],
        protocol: "tcp".to_string(),
    });

    // ========== ZEROMQ ==========

    // ZeroMQ
    signatures.push(ServiceSignature {
        service_name: "zeromq".to_string(),
        probe_name: "ZeroMQ".to_string(),
        pattern: r"ZMTP/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ZeroMQ".to_string()),
            version: Some("protocol $1".to_string()),
            info: Some("High-performance asynchronous messaging".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:zeromq:zeromq".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // ========== REDIS STREAMS ==========

    // Redis Streams
    signatures.push(ServiceSignature {
        service_name: "redis-streams".to_string(),
        probe_name: "Redis".to_string(),
        pattern: r"redis_version:([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Redis Streams".to_string()),
            version: Some("$1".to_string()),
            info: Some("Log-style data structure".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:redis:redis:$1".to_string()],
        }),
        ports: vec![6379],
        protocol: "tcp".to_string(),
    });

    // ========== MQTT BROKERS ==========

    // Mosquitto MQTT Broker
    signatures.push(ServiceSignature {
        service_name: "mosquitto".to_string(),
        probe_name: "MQTT".to_string(),
        pattern: r"mosquitto version ([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Eclipse Mosquitto".to_string()),
            version: Some("$1".to_string()),
            info: Some("MQTT message broker".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:eclipse:mosquitto:$1".to_string()],
        }),
        ports: vec![1883, 8883],
        protocol: "tcp".to_string(),
    });

    // HiveMQ
    signatures.push(ServiceSignature {
        service_name: "hivemq".to_string(),
        probe_name: "MQTT".to_string(),
        pattern: r"HiveMQ.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("HiveMQ".to_string()),
            version: Some("$1".to_string()),
            info: Some("Enterprise MQTT broker".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:hivemq:hivemq:$1".to_string()],
        }),
        ports: vec![1883, 8883],
        protocol: "tcp".to_string(),
    });

    // EMQX
    signatures.push(ServiceSignature {
        service_name: "emqx".to_string(),
        probe_name: "MQTT".to_string(),
        pattern: r"EMQX.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("EMQX".to_string()),
            version: Some("$1".to_string()),
            info: Some("Scalable MQTT broker".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:emqx:emqx:$1".to_string()],
        }),
        ports: vec![1883, 8883, 8083, 8084],
        protocol: "tcp".to_string(),
    });

    // VerneMQ
    signatures.push(ServiceSignature {
        service_name: "vernemq".to_string(),
        probe_name: "MQTT".to_string(),
        pattern: r"VerneMQ".to_string(),
        version_info: Some(VersionInfo {
            product: Some("VerneMQ".to_string()),
            version: None,
            info: Some("Distributed MQTT broker".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:vernemq:vernemq".to_string()],
        }),
        ports: vec![1883, 8883],
        protocol: "tcp".to_string(),
    });

    // ========== ROCKETMQ ==========

    // Apache RocketMQ NameServer
    signatures.push(ServiceSignature {
        service_name: "rocketmq-nameserver".to_string(),
        probe_name: "RocketMQ".to_string(),
        pattern: r"RocketMQ.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache RocketMQ NameServer".to_string()),
            version: Some("$1".to_string()),
            info: Some("Routing information center".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:rocketmq:$1".to_string()],
        }),
        ports: vec![9876],
        protocol: "tcp".to_string(),
    });

    // RocketMQ Broker
    signatures.push(ServiceSignature {
        service_name: "rocketmq-broker".to_string(),
        probe_name: "RocketMQ".to_string(),
        pattern: r"RocketMQ.*broker".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache RocketMQ Broker".to_string()),
            version: None,
            info: Some("Message store and delivery".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:rocketmq".to_string()],
        }),
        ports: vec![10911, 10909],
        protocol: "tcp".to_string(),
    });

    // RocketMQ Console
    signatures.push(ServiceSignature {
        service_name: "rocketmq-console".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"rocketmq.*console".to_string(),
        version_info: Some(VersionInfo {
            product: Some("RocketMQ Console".to_string()),
            version: None,
            info: Some("Management UI".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:rocketmq".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // ========== NSQ ==========

    // NSQd (daemon)
    signatures.push(ServiceSignature {
        service_name: "nsqd".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"([0-9.]+)".*nsqd"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("NSQd".to_string()),
            version: Some("$1".to_string()),
            info: Some("NSQ daemon".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nsq:nsq:$1".to_string()],
        }),
        ports: vec![4150, 4151],
        protocol: "tcp".to_string(),
    });

    // NSQLookupd
    signatures.push(ServiceSignature {
        service_name: "nsqlookupd".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"nsqlookupd".to_string(),
        version_info: Some(VersionInfo {
            product: Some("NSQLookupd".to_string()),
            version: None,
            info: Some("NSQ topology service".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nsq:nsq".to_string()],
        }),
        ports: vec![4160, 4161],
        protocol: "tcp".to_string(),
    });

    // NSQAdmin
    signatures.push(ServiceSignature {
        service_name: "nsqadmin".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"nsqadmin".to_string(),
        version_info: Some(VersionInfo {
            product: Some("NSQAdmin".to_string()),
            version: None,
            info: Some("NSQ web UI".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nsq:nsq".to_string()],
        }),
        ports: vec![4171],
        protocol: "tcp".to_string(),
    });

    // ========== BEANSTALKD ==========

    // Beanstalkd
    signatures.push(ServiceSignature {
        service_name: "beanstalkd".to_string(),
        probe_name: "Beanstalk".to_string(),
        pattern: r"beanstalkd ([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Beanstalkd".to_string()),
            version: Some("$1".to_string()),
            info: Some("Simple work queue".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:beanstalkd:beanstalkd:$1".to_string()],
        }),
        ports: vec![11300],
        protocol: "tcp".to_string(),
    });

    // ========== CLOUD MESSAGE QUEUES (EMULATORS) ==========

    // Amazon SQS (ElasticMQ emulator)
    signatures.push(ServiceSignature {
        service_name: "elasticmq".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"ElasticMQ.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ElasticMQ".to_string()),
            version: Some("$1".to_string()),
            info: Some("Amazon SQS emulator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:softwaremill:elasticmq:$1".to_string()],
        }),
        ports: vec![9324],
        protocol: "tcp".to_string(),
    });

    // AWS SQS LocalStack
    signatures.push(ServiceSignature {
        service_name: "localstack-sqs".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"LocalStack.*sqs".to_string(),
        version_info: Some(VersionInfo {
            product: Some("LocalStack SQS".to_string()),
            version: None,
            info: Some("AWS SQS local testing".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:localstack:localstack".to_string()],
        }),
        ports: vec![4566],
        protocol: "tcp".to_string(),
    });

    // Google Cloud Pub/Sub Emulator
    signatures.push(ServiceSignature {
        service_name: "pubsub-emulator".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Cloud Pub/Sub Emulator".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Google Cloud Pub/Sub Emulator".to_string()),
            version: None,
            info: Some("GCP Pub/Sub local testing".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:google:cloud_pubsub".to_string()],
        }),
        ports: vec![8085],
        protocol: "tcp".to_string(),
    });

    // Azure Service Bus (Emulator)
    signatures.push(ServiceSignature {
        service_name: "servicebus-emulator".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Service Bus Emulator".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Azure Service Bus Emulator".to_string()),
            version: None,
            info: Some("Azure messaging emulator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:azure_service_bus".to_string()],
        }),
        ports: vec![5672],
        protocol: "tcp".to_string(),
    });

    // ========== TASK QUEUES ==========

    // Celery (via Flower monitoring)
    signatures.push(ServiceSignature {
        service_name: "celery-flower".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Flower.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Celery Flower".to_string()),
            version: Some("$1".to_string()),
            info: Some("Celery monitoring tool".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:celery:flower:$1".to_string()],
        }),
        ports: vec![5555],
        protocol: "tcp".to_string(),
    });

    // Sidekiq (Ruby background jobs via Web UI)
    signatures.push(ServiceSignature {
        service_name: "sidekiq".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Sidekiq.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Sidekiq".to_string()),
            version: Some("$1".to_string()),
            info: Some("Ruby background job processor".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:sidekiq:sidekiq:$1".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // Bull Board (Node.js queue UI)
    signatures.push(ServiceSignature {
        service_name: "bull-board".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Bull Board|bull-board".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Bull Board".to_string()),
            version: None,
            info: Some("Queue monitoring UI".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:bull:bull_board".to_string()],
        }),
        ports: vec![3000],
        protocol: "tcp".to_string(),
    });

    // Resque (Ruby/Redis queue)
    signatures.push(ServiceSignature {
        service_name: "resque-web".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Resque".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Resque Web".to_string()),
            version: None,
            info: Some("Redis-backed job queue UI".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:resque:resque".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // ========== STREAMING PLATFORMS ==========

    // Apache Flink JobManager
    signatures.push(ServiceSignature {
        service_name: "flink-jobmanager".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"([0-9.]+)".*flink"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache Flink JobManager".to_string()),
            version: Some("$1".to_string()),
            info: Some("Stream processing framework".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:flink:$1".to_string()],
        }),
        ports: vec![8081],
        protocol: "tcp".to_string(),
    });

    // Apache Spark Streaming
    signatures.push(ServiceSignature {
        service_name: "spark-streaming".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Spark.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache Spark".to_string()),
            version: Some("$1".to_string()),
            info: Some("Real-time stream processing".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:spark:$1".to_string()],
        }),
        ports: vec![4040, 8080],
        protocol: "tcp".to_string(),
    });

    // Redpanda (Kafka-compatible)
    signatures.push(ServiceSignature {
        service_name: "redpanda".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Redpanda.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Redpanda".to_string()),
            version: Some("$1".to_string()),
            info: Some("Kafka-compatible streaming platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:redpanda:redpanda:$1".to_string()],
        }),
        ports: vec![9092, 9644],
        protocol: "tcp".to_string(),
    });

    // Apache Storm Nimbus
    signatures.push(ServiceSignature {
        service_name: "storm-nimbus".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Storm Nimbus".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache Storm Nimbus".to_string()),
            version: None,
            info: Some("Distributed real-time computation".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:storm".to_string()],
        }),
        ports: vec![6627],
        protocol: "tcp".to_string(),
    });

    // ========== ENTERPRISE MESSAGE BUSES ==========

    // IBM MQ
    signatures.push(ServiceSignature {
        service_name: "ibm-mq".to_string(),
        probe_name: "IBMMQ".to_string(),
        pattern: r"IBM MQ|WebSphere MQ".to_string(),
        version_info: Some(VersionInfo {
            product: Some("IBM MQ".to_string()),
            version: None,
            info: Some("Enterprise message queue".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ibm:websphere_mq".to_string()],
        }),
        ports: vec![1414],
        protocol: "tcp".to_string(),
    });

    // TIBCO EMS
    signatures.push(ServiceSignature {
        service_name: "tibco-ems".to_string(),
        probe_name: "TIBCO".to_string(),
        pattern: r"TIBCO Enterprise Message Service".to_string(),
        version_info: Some(VersionInfo {
            product: Some("TIBCO EMS".to_string()),
            version: None,
            info: Some("Enterprise messaging system".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:tibco:enterprise_message_service".to_string()],
        }),
        ports: vec![7222],
        protocol: "tcp".to_string(),
    });

    // Oracle Advanced Queuing
    signatures.push(ServiceSignature {
        service_name: "oracle-aq".to_string(),
        probe_name: "Oracle".to_string(),
        pattern: r"Oracle.*AQ|Advanced Queuing".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Oracle Advanced Queuing".to_string()),
            version: None,
            info: Some("Database-integrated messaging".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:oracle:advanced_queuing".to_string()],
        }),
        ports: vec![1521],
        protocol: "tcp".to_string(),
    });

    signatures
}
