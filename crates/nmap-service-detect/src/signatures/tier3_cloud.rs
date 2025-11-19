use crate::signatures::{ServiceSignature, VersionInfo};

/// Tier 3 Cloud & Enterprise Services
/// Message queues, proxies, monitoring, directory services, and cloud platforms
pub fn load_tier3_cloud_signatures() -> Vec<ServiceSignature> {
    let mut signatures = Vec::new();

    // ========== MESSAGE QUEUES ==========

    // RabbitMQ
    signatures.push(ServiceSignature {
        service_name: "rabbitmq".to_string(),
        probe_name: "AMQP".to_string(),
        pattern: r"AMQP.*RabbitMQ".to_string(),
        version_info: Some(VersionInfo {
            product: Some("RabbitMQ".to_string()),
            version: None,
            info: Some("AMQP message broker".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:pivotal_software:rabbitmq".to_string()],
        }),
        ports: vec![5672, 15672],
        protocol: "tcp".to_string(),
    });

    // Apache Kafka
    signatures.push(ServiceSignature {
        service_name: "kafka".to_string(),
        probe_name: "Kafka".to_string(),
        pattern: r"Kafka".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache Kafka".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:kafka".to_string()],
        }),
        ports: vec![9092],
        protocol: "tcp".to_string(),
    });

    // ActiveMQ
    signatures.push(ServiceSignature {
        service_name: "activemq".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"ActiveMQ".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache ActiveMQ".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:activemq".to_string()],
        }),
        ports: vec![61616, 8161],
        protocol: "tcp".to_string(),
    });

    // ZeroMQ
    signatures.push(ServiceSignature {
        service_name: "zeromq".to_string(),
        probe_name: "ZeroMQ".to_string(),
        pattern: r"ZMTP".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ZeroMQ".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:zeromq:zeromq".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // NATS
    signatures.push(ServiceSignature {
        service_name: "nats".to_string(),
        probe_name: "NATS".to_string(),
        pattern: r"INFO.*nats.*version.*([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("NATS".to_string()),
            version: Some("$1".to_string()),
            info: Some("Message broker".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nats:nats-server:$1".to_string()],
        }),
        ports: vec![4222, 6222, 8222],
        protocol: "tcp".to_string(),
    });

    // Apache Pulsar
    signatures.push(ServiceSignature {
        service_name: "pulsar".to_string(),
        probe_name: "Pulsar".to_string(),
        pattern: r"Pulsar".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache Pulsar".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:pulsar".to_string()],
        }),
        ports: vec![6650, 8080],
        protocol: "tcp".to_string(),
    });

    // MQTT
    signatures.push(ServiceSignature {
        service_name: "mqtt".to_string(),
        probe_name: "MQTT".to_string(),
        pattern: r"MQTT.*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("MQTT broker".to_string()),
            version: None,
            info: Some("IoT messaging protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mqtt:mqtt".to_string()],
        }),
        ports: vec![1883, 8883],
        protocol: "tcp".to_string(),
    });

    // Redis Pub/Sub
    signatures.push(ServiceSignature {
        service_name: "redis-pubsub".to_string(),
        probe_name: "Redis".to_string(),
        pattern: r"redis.*pub.*sub".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Redis Pub/Sub".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:redis:redis".to_string()],
        }),
        ports: vec![6379],
        protocol: "tcp".to_string(),
    });

    // RocketMQ
    signatures.push(ServiceSignature {
        service_name: "rocketmq".to_string(),
        probe_name: "RocketMQ".to_string(),
        pattern: r"RocketMQ".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache RocketMQ".to_string()),
            version: None,
            info: Some("Distributed messaging platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:rocketmq".to_string()],
        }),
        ports: vec![9876, 10911],
        protocol: "tcp".to_string(),
    });

    // NSQ
    signatures.push(ServiceSignature {
        service_name: "nsq".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"nsqd".to_string(),
        version_info: Some(VersionInfo {
            product: Some("NSQ".to_string()),
            version: None,
            info: Some("Realtime distributed messaging platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nsq:nsq".to_string()],
        }),
        ports: vec![4150, 4151],
        protocol: "tcp".to_string(),
    });

    // Beanstalkd
    signatures.push(ServiceSignature {
        service_name: "beanstalkd".to_string(),
        probe_name: "Beanstalk".to_string(),
        pattern: r"beanstalkd".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Beanstalkd".to_string()),
            version: None,
            info: Some("Simple work queue".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:beanstalkd:beanstalkd".to_string()],
        }),
        ports: vec![11300],
        protocol: "tcp".to_string(),
    });

    // Amazon SQS emulator (ElasticMQ)
    signatures.push(ServiceSignature {
        service_name: "sqs-emulator".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"ElasticMQ|X-Amzn-RequestId.*sqs".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Amazon SQS Emulator".to_string()),
            version: None,
            info: Some("Message queue service emulator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:amazon:sqs".to_string()],
        }),
        ports: vec![9324],
        protocol: "tcp".to_string(),
    });

    // Google Pub/Sub emulator
    signatures.push(ServiceSignature {
        service_name: "pubsub-emulator".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Cloud Pub/Sub Emulator".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Google Cloud Pub/Sub Emulator".to_string()),
            version: None,
            info: Some("Message queue service emulator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:google:cloud_pubsub".to_string()],
        }),
        ports: vec![8085],
        protocol: "tcp".to_string(),
    });

    // Azure Service Bus emulator
    signatures.push(ServiceSignature {
        service_name: "servicebus-emulator".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Service Bus Emulator|ServiceBusEmulator".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Azure Service Bus Emulator".to_string()),
            version: None,
            info: Some("Message broker emulator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:azure_service_bus".to_string()],
        }),
        ports: vec![5672],
        protocol: "tcp".to_string(),
    });

    // Celery (via Flower monitoring)
    signatures.push(ServiceSignature {
        service_name: "celery".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Flower.*Celery".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Celery".to_string()),
            version: None,
            info: Some("Distributed task queue".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:celery:celery".to_string()],
        }),
        ports: vec![5555],
        protocol: "tcp".to_string(),
    });

    // ========== PROXIES & LOAD BALANCERS ==========

    // Squid
    signatures.push(ServiceSignature {
        service_name: "http-proxy".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: squid/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Squid http proxy".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:squid-cache:squid:$1".to_string()],
        }),
        ports: vec![3128, 8080],
        protocol: "tcp".to_string(),
    });

    // HAProxy
    signatures.push(ServiceSignature {
        service_name: "http-proxy".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"HAProxy".to_string(),
        version_info: Some(VersionInfo {
            product: Some("HAProxy".to_string()),
            version: None,
            info: Some("load balancer".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:haproxy:haproxy".to_string()],
        }),
        ports: vec![80, 443, 8080],
        protocol: "tcp".to_string(),
    });

    // Varnish
    signatures.push(ServiceSignature {
        service_name: "http-proxy".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"X-Varnish|Via:.*varnish".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Varnish http accelerator".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:varnish-cache:varnish".to_string()],
        }),
        ports: vec![80, 6081, 6082],
        protocol: "tcp".to_string(),
    });

    // Traefik
    signatures.push(ServiceSignature {
        service_name: "http-proxy".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Traefik".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Traefik".to_string()),
            version: None,
            info: Some("Reverse proxy and load balancer".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:traefik:traefik".to_string()],
        }),
        ports: vec![80, 443, 8080],
        protocol: "tcp".to_string(),
    });

    // Envoy
    signatures.push(ServiceSignature {
        service_name: "http-proxy".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"server: envoy".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Envoy proxy".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:envoyproxy:envoy".to_string()],
        }),
        ports: vec![10000, 15000],
        protocol: "tcp".to_string(),
    });

    // Nginx as Reverse Proxy
    signatures.push(ServiceSignature {
        service_name: "http-proxy".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: nginx.*X-Proxy".to_string(),
        version_info: Some(VersionInfo {
            product: Some("nginx reverse proxy".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nginx:nginx".to_string()],
        }),
        ports: vec![80, 443, 8080],
        protocol: "tcp".to_string(),
    });

    // ========== DIRECTORY SERVICES ==========

    // OpenLDAP
    signatures.push(ServiceSignature {
        service_name: "ldap".to_string(),
        probe_name: "LDAP".to_string(),
        pattern: r"OpenLDAP.*([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OpenLDAP".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:openldap:openldap:$1".to_string()],
        }),
        ports: vec![389, 636],
        protocol: "tcp".to_string(),
    });

    // Active Directory
    signatures.push(ServiceSignature {
        service_name: "ldap".to_string(),
        probe_name: "LDAP".to_string(),
        pattern: r"Active Directory".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Microsoft Active Directory LDAP".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: Some("Windows".to_string()),
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:active_directory".to_string()],
        }),
        ports: vec![389, 636, 3268, 3269],
        protocol: "tcp".to_string(),
    });

    // Kerberos
    signatures.push(ServiceSignature {
        service_name: "kerberos".to_string(),
        probe_name: "Kerberos".to_string(),
        pattern: r"krb5".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kerberos".to_string()),
            version: None,
            info: Some("Authentication service".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:mit:kerberos".to_string()],
        }),
        ports: vec![88],
        protocol: "tcp".to_string(),
    });

    // NIS
    signatures.push(ServiceSignature {
        service_name: "nis".to_string(),
        probe_name: "NIS".to_string(),
        pattern: r"ypbind".to_string(),
        version_info: Some(VersionInfo {
            product: Some("NIS".to_string()),
            version: None,
            info: Some("Network Information Service".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nis:nis".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // RADIUS
    signatures.push(ServiceSignature {
        service_name: "radius".to_string(),
        probe_name: "RADIUS".to_string(),
        pattern: r".*".to_string(),
        version_info: Some(VersionInfo {
            product: Some("RADIUS".to_string()),
            version: None,
            info: Some("Authentication server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:radius:radius".to_string()],
        }),
        ports: vec![1812, 1813],
        protocol: "udp".to_string(),
    });

    // ========== MONITORING & MANAGEMENT ==========

    // Nagios
    signatures.push(ServiceSignature {
        service_name: "nagios".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Nagios".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Nagios".to_string()),
            version: None,
            info: Some("Monitoring system".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nagios:nagios".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // Zabbix
    signatures.push(ServiceSignature {
        service_name: "zabbix".to_string(),
        probe_name: "Zabbix".to_string(),
        pattern: r"ZBXD".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Zabbix".to_string()),
            version: None,
            info: Some("Monitoring system".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:zabbix:zabbix".to_string()],
        }),
        ports: vec![10050, 10051],
        protocol: "tcp".to_string(),
    });

    // Prometheus
    signatures.push(ServiceSignature {
        service_name: "prometheus".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"prometheus".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Prometheus".to_string()),
            version: None,
            info: Some("Monitoring system and time series database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:prometheus:prometheus".to_string()],
        }),
        ports: vec![9090],
        protocol: "tcp".to_string(),
    });

    // Grafana
    signatures.push(ServiceSignature {
        service_name: "grafana".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Grafana".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Grafana".to_string()),
            version: None,
            info: Some("Analytics and monitoring dashboard".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:grafana:grafana".to_string()],
        }),
        ports: vec![3000],
        protocol: "tcp".to_string(),
    });

    // Netdata
    signatures.push(ServiceSignature {
        service_name: "netdata".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"netdata".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Netdata".to_string()),
            version: None,
            info: Some("Real-time performance monitoring".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:netdata:netdata".to_string()],
        }),
        ports: vec![19999],
        protocol: "tcp".to_string(),
    });

    // Datadog Agent
    signatures.push(ServiceSignature {
        service_name: "datadog".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Datadog".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Datadog Agent".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:datadog:datadog_agent".to_string()],
        }),
        ports: vec![8125, 8126],
        protocol: "tcp".to_string(),
    });

    // New Relic
    signatures.push(ServiceSignature {
        service_name: "newrelic".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"New Relic".to_string(),
        version_info: Some(VersionInfo {
            product: Some("New Relic".to_string()),
            version: None,
            info: Some("Application performance monitoring".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:newrelic:newrelic".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // ========== DEVOPS & INFRASTRUCTURE ==========

    // Docker API
    signatures.push(ServiceSignature {
        service_name: "docker".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""Platform".*"Name":"Docker""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Docker API".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:docker:docker".to_string()],
        }),
        ports: vec![2375, 2376],
        protocol: "tcp".to_string(),
    });

    // Kubernetes API
    signatures.push(ServiceSignature {
        service_name: "kubernetes".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""major":"[0-9]+".*"minor":"[0-9]+""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kubernetes API".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:kubernetes:kubernetes".to_string()],
        }),
        ports: vec![6443, 8443, 443],
        protocol: "tcp".to_string(),
    });

    // Git
    signatures.push(ServiceSignature {
        service_name: "git".to_string(),
        probe_name: "Git".to_string(),
        pattern: r"git".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Git".to_string()),
            version: None,
            info: Some("Version control system".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:git:git".to_string()],
        }),
        ports: vec![9418],
        protocol: "tcp".to_string(),
    });

    // Subversion (SVN)
    signatures.push(ServiceSignature {
        service_name: "svn".to_string(),
        probe_name: "SVN".to_string(),
        pattern: r"SVN".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Subversion".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:subversion".to_string()],
        }),
        ports: vec![3690],
        protocol: "tcp".to_string(),
    });

    // Jenkins
    signatures.push(ServiceSignature {
        service_name: "jenkins".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"X-Jenkins.*([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Jenkins".to_string()),
            version: Some("$1".to_string()),
            info: Some("Continuous integration server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:jenkins:jenkins:$1".to_string()],
        }),
        ports: vec![8080, 8081],
        protocol: "tcp".to_string(),
    });

    // GitLab
    signatures.push(ServiceSignature {
        service_name: "gitlab".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"GitLab".to_string(),
        version_info: Some(VersionInfo {
            product: Some("GitLab".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:gitlab:gitlab".to_string()],
        }),
        ports: vec![80, 443],
        protocol: "tcp".to_string(),
    });

    // Consul
    signatures.push(ServiceSignature {
        service_name: "consul".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Consul".to_string(),
        version_info: Some(VersionInfo {
            product: Some("HashiCorp Consul".to_string()),
            version: None,
            info: Some("Service mesh solution".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:hashicorp:consul".to_string()],
        }),
        ports: vec![8500, 8600],
        protocol: "tcp".to_string(),
    });

    // Etcd
    signatures.push(ServiceSignature {
        service_name: "etcd".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""etcdserver":"([0-9.]+)""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("etcd".to_string()),
            version: Some("$1".to_string()),
            info: Some("Distributed key-value store".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:etcd:etcd:$1".to_string()],
        }),
        ports: vec![2379, 2380],
        protocol: "tcp".to_string(),
    });

    // ========== ANALYTICS & LOGGING ==========

    // Elasticsearch Kibana
    signatures.push(ServiceSignature {
        service_name: "kibana".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""name":"Kibana""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kibana".to_string()),
            version: None,
            info: Some("Elasticsearch visualization".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:elasticsearch:kibana".to_string()],
        }),
        ports: vec![5601],
        protocol: "tcp".to_string(),
    });

    // Logstash
    signatures.push(ServiceSignature {
        service_name: "logstash".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Logstash".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Logstash".to_string()),
            version: None,
            info: Some("Log processing pipeline".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:elasticsearch:logstash".to_string()],
        }),
        ports: vec![9600],
        protocol: "tcp".to_string(),
    });

    // SonarQube
    signatures.push(ServiceSignature {
        service_name: "sonarqube".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"SonarQube".to_string(),
        version_info: Some(VersionInfo {
            product: Some("SonarQube".to_string()),
            version: None,
            info: Some("Code quality platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:sonarsource:sonarqube".to_string()],
        }),
        ports: vec![9000],
        protocol: "tcp".to_string(),
    });

    // Splunk
    signatures.push(ServiceSignature {
        service_name: "splunk".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Splunk".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Splunk".to_string()),
            version: None,
            info: Some("Log analysis platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:splunk:splunk".to_string()],
        }),
        ports: vec![8000, 8089],
        protocol: "tcp".to_string(),
    });

    // ========== KUBERNETES COMPONENTS ==========

    // kubelet
    signatures.push(ServiceSignature {
        service_name: "kubelet".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"kubelet".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kubernetes kubelet".to_string()),
            version: None,
            info: Some("Node agent".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:kubernetes:kubernetes".to_string()],
        }),
        ports: vec![10250, 10255],
        protocol: "tcp".to_string(),
    });

    // kube-proxy
    signatures.push(ServiceSignature {
        service_name: "kube-proxy".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"kube-proxy".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kubernetes kube-proxy".to_string()),
            version: None,
            info: Some("Network proxy".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:kubernetes:kubernetes".to_string()],
        }),
        ports: vec![10256],
        protocol: "tcp".to_string(),
    });

    // kube-scheduler
    signatures.push(ServiceSignature {
        service_name: "kube-scheduler".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"kube-scheduler".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kubernetes scheduler".to_string()),
            version: None,
            info: Some("Pod scheduler".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:kubernetes:kubernetes".to_string()],
        }),
        ports: vec![10259],
        protocol: "tcp".to_string(),
    });

    // kube-controller-manager
    signatures.push(ServiceSignature {
        service_name: "kube-controller-manager".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"kube-controller-manager".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kubernetes controller manager".to_string()),
            version: None,
            info: Some("Control plane component".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:kubernetes:kubernetes".to_string()],
        }),
        ports: vec![10257],
        protocol: "tcp".to_string(),
    });

    // ========== KUBERNETES INGRESS CONTROLLERS ==========

    // NGINX Ingress Controller
    signatures.push(ServiceSignature {
        service_name: "nginx-ingress".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"nginx-ingress-controller".to_string(),
        version_info: Some(VersionInfo {
            product: Some("NGINX Ingress Controller".to_string()),
            version: None,
            info: Some("Kubernetes ingress".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nginx:ingress_controller".to_string()],
        }),
        ports: vec![80, 443, 10254],
        protocol: "tcp".to_string(),
    });

    // Traefik Ingress
    signatures.push(ServiceSignature {
        service_name: "traefik-ingress".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Traefik.*kubernetes".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Traefik Ingress Controller".to_string()),
            version: None,
            info: Some("Cloud-native ingress".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:traefik:traefik".to_string()],
        }),
        ports: vec![80, 443, 9000],
        protocol: "tcp".to_string(),
    });

    // HAProxy Ingress
    signatures.push(ServiceSignature {
        service_name: "haproxy-ingress".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"haproxy-ingress".to_string(),
        version_info: Some(VersionInfo {
            product: Some("HAProxy Ingress Controller".to_string()),
            version: None,
            info: Some("Kubernetes ingress".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:haproxy:ingress".to_string()],
        }),
        ports: vec![80, 443, 1024],
        protocol: "tcp".to_string(),
    });

    // Contour Ingress
    signatures.push(ServiceSignature {
        service_name: "contour-ingress".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"contour".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Contour Ingress Controller".to_string()),
            version: None,
            info: Some("Envoy-based ingress".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:vmware:contour".to_string()],
        }),
        ports: vec![8000, 8001],
        protocol: "tcp".to_string(),
    });

    // ========== SERVICE MESHES ==========

    // Istio Pilot
    signatures.push(ServiceSignature {
        service_name: "istio-pilot".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"istio.*pilot".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Istio Pilot".to_string()),
            version: None,
            info: Some("Service mesh control plane".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:istio:istio".to_string()],
        }),
        ports: vec![15010, 15011, 15012],
        protocol: "tcp".to_string(),
    });

    // Istio Envoy Proxy
    signatures.push(ServiceSignature {
        service_name: "istio-proxy".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"envoy.*istio".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Istio Envoy Proxy".to_string()),
            version: None,
            info: Some("Service mesh sidecar".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:istio:istio".to_string()],
        }),
        ports: vec![15001, 15006, 15020, 15021, 15090],
        protocol: "tcp".to_string(),
    });

    // Linkerd Proxy
    signatures.push(ServiceSignature {
        service_name: "linkerd-proxy".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"linkerd".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Linkerd Proxy".to_string()),
            version: None,
            info: Some("Service mesh for Kubernetes".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:linkerd:linkerd".to_string()],
        }),
        ports: vec![4140, 4143, 4191],
        protocol: "tcp".to_string(),
    });

    // Consul Connect
    signatures.push(ServiceSignature {
        service_name: "consul-connect".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"consul.*connect".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Consul Connect".to_string()),
            version: None,
            info: Some("Service mesh solution".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:hashicorp:consul".to_string()],
        }),
        ports: vec![8500, 8501, 8502],
        protocol: "tcp".to_string(),
    });

    // Kuma Control Plane
    signatures.push(ServiceSignature {
        service_name: "kuma-cp".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"kuma".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kuma Control Plane".to_string()),
            version: None,
            info: Some("Universal service mesh".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:kong:kuma".to_string()],
        }),
        ports: vec![5681],
        protocol: "tcp".to_string(),
    });

    // ========== DOCKER ECOSYSTEM ==========

    // Docker Swarm Manager
    signatures.push(ServiceSignature {
        service_name: "docker-swarm".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"swarm".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Docker Swarm".to_string()),
            version: None,
            info: Some("Container orchestration".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:docker:swarm".to_string()],
        }),
        ports: vec![2377],
        protocol: "tcp".to_string(),
    });

    // Docker Registry
    signatures.push(ServiceSignature {
        service_name: "docker-registry".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""name":"docker-registry""#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Docker Registry".to_string()),
            version: None,
            info: Some("Container image registry".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:docker:registry".to_string()],
        }),
        ports: vec![5000],
        protocol: "tcp".to_string(),
    });

    // Docker Notary
    signatures.push(ServiceSignature {
        service_name: "docker-notary".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"notary".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Docker Notary".to_string()),
            version: None,
            info: Some("Content trust for Docker".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:docker:notary".to_string()],
        }),
        ports: vec![4443],
        protocol: "tcp".to_string(),
    });

    // Portainer
    signatures.push(ServiceSignature {
        service_name: "portainer".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Portainer".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Portainer".to_string()),
            version: None,
            info: Some("Container management UI".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:portainer:portainer".to_string()],
        }),
        ports: vec![9000, 9443],
        protocol: "tcp".to_string(),
    });

    // ========== CONTAINER RUNTIMES ==========

    // containerd
    signatures.push(ServiceSignature {
        service_name: "containerd".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"containerd".to_string(),
        version_info: Some(VersionInfo {
            product: Some("containerd".to_string()),
            version: None,
            info: Some("Container runtime".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:containerd:containerd".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // CRI-O
    signatures.push(ServiceSignature {
        service_name: "crio".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"cri-o".to_string(),
        version_info: Some(VersionInfo {
            product: Some("CRI-O".to_string()),
            version: None,
            info: Some("Kubernetes container runtime".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:cri-o:cri-o".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // ========== CLOUD-NATIVE PLATFORMS ==========

    // Rancher
    signatures.push(ServiceSignature {
        service_name: "rancher".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Rancher.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Rancher".to_string()),
            version: Some("$1".to_string()),
            info: Some("Kubernetes management platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:rancher:rancher:$1".to_string()],
        }),
        ports: vec![80, 443],
        protocol: "tcp".to_string(),
    });

    // OpenShift API
    signatures.push(ServiceSignature {
        service_name: "openshift".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"OpenShift".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Red Hat OpenShift".to_string()),
            version: None,
            info: Some("Kubernetes platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:redhat:openshift".to_string()],
        }),
        ports: vec![6443, 8443],
        protocol: "tcp".to_string(),
    });

    // Nomad
    signatures.push(ServiceSignature {
        service_name: "nomad".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Nomad.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("HashiCorp Nomad".to_string()),
            version: Some("$1".to_string()),
            info: Some("Workload orchestrator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:hashicorp:nomad:$1".to_string()],
        }),
        ports: vec![4646, 4647, 4648],
        protocol: "tcp".to_string(),
    });

    // Vault
    signatures.push(ServiceSignature {
        service_name: "vault".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"([0-9.]+)".*vault"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("HashiCorp Vault".to_string()),
            version: Some("$1".to_string()),
            info: Some("Secrets management".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:hashicorp:vault:$1".to_string()],
        }),
        ports: vec![8200, 8201],
        protocol: "tcp".to_string(),
    });

    // ========== GITOPS & CI/CD ==========

    // ArgoCD Server
    signatures.push(ServiceSignature {
        service_name: "argocd".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"argocd".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Argo CD".to_string()),
            version: None,
            info: Some("GitOps continuous delivery".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:argoproj:argo_cd".to_string()],
        }),
        ports: vec![8080, 8083],
        protocol: "tcp".to_string(),
    });

    // Flux
    signatures.push(ServiceSignature {
        service_name: "flux".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"flux".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Flux".to_string()),
            version: None,
            info: Some("GitOps toolkit for Kubernetes".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:fluxcd:flux".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // Tekton Dashboard
    signatures.push(ServiceSignature {
        service_name: "tekton-dashboard".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Tekton".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Tekton Dashboard".to_string()),
            version: None,
            info: Some("Kubernetes-native CI/CD".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:tekton:tekton".to_string()],
        }),
        ports: vec![9097],
        protocol: "tcp".to_string(),
    });

    // Spinnaker
    signatures.push(ServiceSignature {
        service_name: "spinnaker".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Spinnaker".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Spinnaker".to_string()),
            version: None,
            info: Some("Multi-cloud continuous delivery".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:spinnaker:spinnaker".to_string()],
        }),
        ports: vec![9000, 8084],
        protocol: "tcp".to_string(),
    });

    // ========== AWS SERVICES (LOCAL/EMULATOR) ==========

    // LocalStack
    signatures.push(ServiceSignature {
        service_name: "localstack".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"LocalStack.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("LocalStack".to_string()),
            version: Some("$1".to_string()),
            info: Some("AWS cloud emulator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:localstack:localstack:$1".to_string()],
        }),
        ports: vec![4566],
        protocol: "tcp".to_string(),
    });

    // MinIO (S3-compatible)
    signatures.push(ServiceSignature {
        service_name: "minio".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"MinIO.*([0-9]{4}-[0-9]{2}-[0-9]{2})".to_string(),
        version_info: Some(VersionInfo {
            product: Some("MinIO".to_string()),
            version: Some("$1".to_string()),
            info: Some("S3-compatible object storage".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:minio:minio:$1".to_string()],
        }),
        ports: vec![9000, 9001],
        protocol: "tcp".to_string(),
    });

    // AWS S3 LocalStack
    signatures.push(ServiceSignature {
        service_name: "localstack-s3".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"AmazonS3.*LocalStack".to_string(),
        version_info: Some(VersionInfo {
            product: Some("LocalStack S3".to_string()),
            version: None,
            info: Some("S3 emulator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:localstack:localstack".to_string()],
        }),
        ports: vec![4566],
        protocol: "tcp".to_string(),
    });

    // AWS Lambda LocalStack
    signatures.push(ServiceSignature {
        service_name: "localstack-lambda".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Lambda.*LocalStack".to_string(),
        version_info: Some(VersionInfo {
            product: Some("LocalStack Lambda".to_string()),
            version: None,
            info: Some("Lambda emulator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:localstack:localstack".to_string()],
        }),
        ports: vec![4566],
        protocol: "tcp".to_string(),
    });

    // ========== AZURE SERVICES (EMULATOR) ==========

    // Azurite (Azure Storage emulator)
    signatures.push(ServiceSignature {
        service_name: "azurite".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Azurite.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Azurite".to_string()),
            version: Some("$1".to_string()),
            info: Some("Azure Storage emulator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:azurite:$1".to_string()],
        }),
        ports: vec![10000, 10001, 10002],
        protocol: "tcp".to_string(),
    });

    // ========== GCP SERVICES (EMULATOR) ==========

    // Cloud Bigtable Emulator
    signatures.push(ServiceSignature {
        service_name: "bigtable-emulator".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Cloud Bigtable Emulator".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Google Cloud Bigtable Emulator".to_string()),
            version: None,
            info: Some("Bigtable local testing".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:google:cloud_bigtable".to_string()],
        }),
        ports: vec![8086],
        protocol: "tcp".to_string(),
    });

    // Cloud Datastore Emulator
    signatures.push(ServiceSignature {
        service_name: "datastore-emulator".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Cloud Datastore Emulator".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Google Cloud Datastore Emulator".to_string()),
            version: None,
            info: Some("Datastore local testing".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:google:cloud_datastore".to_string()],
        }),
        ports: vec![8081],
        protocol: "tcp".to_string(),
    });

    // ========== API GATEWAYS ==========

    // Kong Gateway
    signatures.push(ServiceSignature {
        service_name: "kong".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"([0-9.]+)".*kong"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kong API Gateway".to_string()),
            version: Some("$1".to_string()),
            info: Some("Cloud-native API gateway".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:konghq:kong:$1".to_string()],
        }),
        ports: vec![8000, 8001, 8443, 8444],
        protocol: "tcp".to_string(),
    });

    // Tyk Gateway
    signatures.push(ServiceSignature {
        service_name: "tyk".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Tyk".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Tyk API Gateway".to_string()),
            version: None,
            info: Some("API management platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:tyk:tyk".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // API Gateway (AWS compatible)
    signatures.push(ServiceSignature {
        service_name: "aws-api-gateway".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"x-amzn-RequestId.*execute-api".to_string(),
        version_info: Some(VersionInfo {
            product: Some("AWS API Gateway".to_string()),
            version: None,
            info: Some("Managed API service".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:amazon:api_gateway".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // KrakenD
    signatures.push(ServiceSignature {
        service_name: "krakend".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"KrakenD".to_string(),
        version_info: Some(VersionInfo {
            product: Some("KrakenD".to_string()),
            version: None,
            info: Some("API gateway and aggregator".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:krakend:krakend".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // ========== SERVERLESS PLATFORMS ==========

    // OpenFaaS Gateway
    signatures.push(ServiceSignature {
        service_name: "openfaas".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"openfaas".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OpenFaaS Gateway".to_string()),
            version: None,
            info: Some("Serverless functions platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:openfaas:openfaas".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // Knative Serving
    signatures.push(ServiceSignature {
        service_name: "knative-serving".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"knative".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Knative Serving".to_string()),
            version: None,
            info: Some("Kubernetes-based serverless".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:knative:knative".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // Fission
    signatures.push(ServiceSignature {
        service_name: "fission".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"fission".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Fission".to_string()),
            version: None,
            info: Some("Serverless framework for Kubernetes".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:fission:fission".to_string()],
        }),
        ports: vec![8888],
        protocol: "tcp".to_string(),
    });

    // Kubeless
    signatures.push(ServiceSignature {
        service_name: "kubeless".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"kubeless".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kubeless".to_string()),
            version: None,
            info: Some("Kubernetes-native serverless framework".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:kubeless:kubeless".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // ========== CLOUD STORAGE ==========

    // Ceph RADOS Gateway
    signatures.push(ServiceSignature {
        service_name: "ceph-radosgw".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"ceph.*rgw".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Ceph RADOS Gateway".to_string()),
            version: None,
            info: Some("Object storage interface".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:redhat:ceph".to_string()],
        }),
        ports: vec![7480, 8080],
        protocol: "tcp".to_string(),
    });

    // Ceph Manager
    signatures.push(ServiceSignature {
        service_name: "ceph-mgr".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"ceph.*manager".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Ceph Manager".to_string()),
            version: None,
            info: Some("Ceph cluster management".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:redhat:ceph".to_string()],
        }),
        ports: vec![7000, 9283],
        protocol: "tcp".to_string(),
    });

    // GlusterFS
    signatures.push(ServiceSignature {
        service_name: "glusterfs".to_string(),
        probe_name: "GlusterFS".to_string(),
        pattern: r"GlusterFS".to_string(),
        version_info: Some(VersionInfo {
            product: Some("GlusterFS".to_string()),
            version: None,
            info: Some("Distributed file system".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:gluster:glusterfs".to_string()],
        }),
        ports: vec![24007, 24008],
        protocol: "tcp".to_string(),
    });

    // Rook Ceph Operator
    signatures.push(ServiceSignature {
        service_name: "rook-ceph".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"rook.*ceph".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Rook Ceph Operator".to_string()),
            version: None,
            info: Some("Ceph on Kubernetes".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:rook:rook".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // Longhorn
    signatures.push(ServiceSignature {
        service_name: "longhorn".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Longhorn".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Longhorn".to_string()),
            version: None,
            info: Some("Cloud-native distributed block storage".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:rancher:longhorn".to_string()],
        }),
        ports: vec![9500],
        protocol: "tcp".to_string(),
    });

    // ========== CERTIFICATE MANAGEMENT ==========

    // cert-manager
    signatures.push(ServiceSignature {
        service_name: "cert-manager".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"cert-manager".to_string(),
        version_info: Some(VersionInfo {
            product: Some("cert-manager".to_string()),
            version: None,
            info: Some("X.509 certificate management for Kubernetes".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:jetstack:cert_manager".to_string()],
        }),
        ports: vec![9402],
        protocol: "tcp".to_string(),
    });

    // Let's Encrypt Boulder
    signatures.push(ServiceSignature {
        service_name: "boulder".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Boulder".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Let's Encrypt Boulder".to_string()),
            version: None,
            info: Some("ACME CA implementation".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:letsencrypt:boulder".to_string()],
        }),
        ports: vec![4001],
        protocol: "tcp".to_string(),
    });

    // External Secrets Operator
    signatures.push(ServiceSignature {
        service_name: "external-secrets".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"external-secrets".to_string(),
        version_info: Some(VersionInfo {
            product: Some("External Secrets Operator".to_string()),
            version: None,
            info: Some("Kubernetes secrets management".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:external_secrets:operator".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // Sealed Secrets Controller
    signatures.push(ServiceSignature {
        service_name: "sealed-secrets".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"sealed-secrets".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Sealed Secrets Controller".to_string()),
            version: None,
            info: Some("Encrypted Kubernetes secrets".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:bitnami:sealed_secrets".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    signatures
}
