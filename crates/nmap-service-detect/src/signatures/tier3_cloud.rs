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

    signatures
}
