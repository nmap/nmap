use crate::signatures::{ServiceSignature, VersionInfo};

/// Tier 2 Monitoring & Observability - Monitoring, metrics, and logging system signatures
/// Covers time-series databases, log aggregation, APM, and infrastructure monitoring
pub fn load_tier2_monitoring_signatures() -> Vec<ServiceSignature> {
    let mut signatures = Vec::new();

    // ========== PROMETHEUS ECOSYSTEM ==========

    // Prometheus Server
    signatures.push(ServiceSignature {
        service_name: "prometheus".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"([0-9.]+)".*prometheus"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Prometheus".to_string()),
            version: Some("$1".to_string()),
            info: Some("Monitoring system and time series database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:prometheus:prometheus:$1".to_string()],
        }),
        ports: vec![9090],
        protocol: "tcp".to_string(),
    });

    // Alertmanager
    signatures.push(ServiceSignature {
        service_name: "alertmanager".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"([0-9.]+)".*alertmanager"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Prometheus Alertmanager".to_string()),
            version: Some("$1".to_string()),
            info: Some("Alert management and routing".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:prometheus:alertmanager:$1".to_string()],
        }),
        ports: vec![9093],
        protocol: "tcp".to_string(),
    });

    // Pushgateway
    signatures.push(ServiceSignature {
        service_name: "pushgateway".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Pushgateway".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Prometheus Pushgateway".to_string()),
            version: None,
            info: Some("Push metrics aggregation".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:prometheus:pushgateway".to_string()],
        }),
        ports: vec![9091],
        protocol: "tcp".to_string(),
    });

    // Thanos Query
    signatures.push(ServiceSignature {
        service_name: "thanos-query".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"thanos.*query".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Thanos Query".to_string()),
            version: None,
            info: Some("Prometheus high availability system".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:thanos:thanos".to_string()],
        }),
        ports: vec![9090, 10902],
        protocol: "tcp".to_string(),
    });

    // Cortex
    signatures.push(ServiceSignature {
        service_name: "cortex".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Cortex".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Cortex".to_string()),
            version: None,
            info: Some("Horizontally scalable Prometheus".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:cortex:cortex".to_string()],
        }),
        ports: vec![9009],
        protocol: "tcp".to_string(),
    });

    // ========== GRAFANA ECOSYSTEM ==========

    // Grafana
    signatures.push(ServiceSignature {
        service_name: "grafana".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"([0-9.]+)".*Grafana"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Grafana".to_string()),
            version: Some("$1".to_string()),
            info: Some("Analytics and monitoring dashboard".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:grafana:grafana:$1".to_string()],
        }),
        ports: vec![3000],
        protocol: "tcp".to_string(),
    });

    // Grafana Loki
    signatures.push(ServiceSignature {
        service_name: "loki".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"loki".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Grafana Loki".to_string()),
            version: None,
            info: Some("Log aggregation system".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:grafana:loki".to_string()],
        }),
        ports: vec![3100],
        protocol: "tcp".to_string(),
    });

    // Grafana Tempo
    signatures.push(ServiceSignature {
        service_name: "tempo".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"tempo".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Grafana Tempo".to_string()),
            version: None,
            info: Some("Distributed tracing backend".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:grafana:tempo".to_string()],
        }),
        ports: vec![3200],
        protocol: "tcp".to_string(),
    });

    // Grafana Mimir
    signatures.push(ServiceSignature {
        service_name: "mimir".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"mimir".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Grafana Mimir".to_string()),
            version: None,
            info: Some("Scalable Prometheus metrics backend".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:grafana:mimir".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // ========== TIME-SERIES DATABASES ==========

    // InfluxDB v1
    signatures.push(ServiceSignature {
        service_name: "influxdb".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"X-Influxdb-Version: 1\.([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("InfluxDB".to_string()),
            version: Some("1.$1".to_string()),
            info: Some("Time series database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:influxdata:influxdb:1.$1".to_string()],
        }),
        ports: vec![8086],
        protocol: "tcp".to_string(),
    });

    // InfluxDB v2
    signatures.push(ServiceSignature {
        service_name: "influxdb2".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"X-Influxdb-Version: 2\.([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("InfluxDB 2.x".to_string()),
            version: Some("2.$1".to_string()),
            info: Some("Time series platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:influxdata:influxdb:2.$1".to_string()],
        }),
        ports: vec![8086],
        protocol: "tcp".to_string(),
    });

    // Telegraf
    signatures.push(ServiceSignature {
        service_name: "telegraf".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Telegraf.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Telegraf".to_string()),
            version: Some("$1".to_string()),
            info: Some("Metrics collection agent".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:influxdata:telegraf:$1".to_string()],
        }),
        ports: vec![8125, 8092, 8094],
        protocol: "tcp".to_string(),
    });

    // VictoriaMetrics
    signatures.push(ServiceSignature {
        service_name: "victoriametrics".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"VictoriaMetrics.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("VictoriaMetrics".to_string()),
            version: Some("$1".to_string()),
            info: Some("Fast time series database".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:victoriametrics:victoriametrics:$1".to_string()],
        }),
        ports: vec![8428],
        protocol: "tcp".to_string(),
    });

    // TimescaleDB
    signatures.push(ServiceSignature {
        service_name: "timescaledb".to_string(),
        probe_name: "PostgreSQL".to_string(),
        pattern: r"TimescaleDB.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("TimescaleDB".to_string()),
            version: Some("$1".to_string()),
            info: Some("PostgreSQL time-series extension".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:timescale:timescaledb:$1".to_string()],
        }),
        ports: vec![5432],
        protocol: "tcp".to_string(),
    });

    // ========== ELK STACK ==========

    // Elasticsearch
    signatures.push(ServiceSignature {
        service_name: "elasticsearch".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version".*"number"\s*:\s*"([0-9.]+)".*elasticsearch"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Elasticsearch".to_string()),
            version: Some("$1".to_string()),
            info: Some("Search and analytics engine".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:elastic:elasticsearch:$1".to_string()],
        }),
        ports: vec![9200, 9300],
        protocol: "tcp".to_string(),
    });

    // Kibana
    signatures.push(ServiceSignature {
        service_name: "kibana".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"([0-9.]+)".*kibana"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kibana".to_string()),
            version: Some("$1".to_string()),
            info: Some("Elasticsearch visualization".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:elastic:kibana:$1".to_string()],
        }),
        ports: vec![5601],
        protocol: "tcp".to_string(),
    });

    // Logstash
    signatures.push(ServiceSignature {
        service_name: "logstash".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r#""version":"([0-9.]+)".*logstash"#.to_string(),
        version_info: Some(VersionInfo {
            product: Some("Logstash".to_string()),
            version: Some("$1".to_string()),
            info: Some("Log processing pipeline".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:elastic:logstash:$1".to_string()],
        }),
        ports: vec![9600, 5044],
        protocol: "tcp".to_string(),
    });

    // Filebeat
    signatures.push(ServiceSignature {
        service_name: "filebeat".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Filebeat.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Filebeat".to_string()),
            version: Some("$1".to_string()),
            info: Some("Log shipper".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:elastic:beats:$1".to_string()],
        }),
        ports: vec![5066],
        protocol: "tcp".to_string(),
    });

    // Metricbeat
    signatures.push(ServiceSignature {
        service_name: "metricbeat".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Metricbeat.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Metricbeat".to_string()),
            version: Some("$1".to_string()),
            info: Some("Metrics shipper".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:elastic:beats:$1".to_string()],
        }),
        ports: vec![5066],
        protocol: "tcp".to_string(),
    });

    // ========== SPLUNK ==========

    // Splunk Enterprise
    signatures.push(ServiceSignature {
        service_name: "splunk".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Splunk.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Splunk Enterprise".to_string()),
            version: Some("$1".to_string()),
            info: Some("Log analysis platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:splunk:splunk:$1".to_string()],
        }),
        ports: vec![8000, 8089],
        protocol: "tcp".to_string(),
    });

    // Splunk Forwarder
    signatures.push(ServiceSignature {
        service_name: "splunk-forwarder".to_string(),
        probe_name: "Splunk".to_string(),
        pattern: r"Splunkd".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Splunk Universal Forwarder".to_string()),
            version: None,
            info: Some("Log forwarder".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:splunk:universal_forwarder".to_string()],
        }),
        ports: vec![9997, 8089],
        protocol: "tcp".to_string(),
    });

    // ========== APM & TRACING ==========

    // Jaeger Query
    signatures.push(ServiceSignature {
        service_name: "jaeger-query".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Jaeger".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Jaeger Query".to_string()),
            version: None,
            info: Some("Distributed tracing system".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:jaegertracing:jaeger".to_string()],
        }),
        ports: vec![16686],
        protocol: "tcp".to_string(),
    });

    // Zipkin
    signatures.push(ServiceSignature {
        service_name: "zipkin".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"zipkin".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Zipkin".to_string()),
            version: None,
            info: Some("Distributed tracing system".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:zipkin:zipkin".to_string()],
        }),
        ports: vec![9411],
        protocol: "tcp".to_string(),
    });

    // OpenTelemetry Collector
    signatures.push(ServiceSignature {
        service_name: "otel-collector".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"otelcol.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OpenTelemetry Collector".to_string()),
            version: Some("$1".to_string()),
            info: Some("Telemetry data collector".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:opentelemetry:collector:$1".to_string()],
        }),
        ports: vec![4317, 4318, 13133],
        protocol: "tcp".to_string(),
    });

    // New Relic Agent
    signatures.push(ServiceSignature {
        service_name: "newrelic-agent".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"New Relic".to_string(),
        version_info: Some(VersionInfo {
            product: Some("New Relic APM".to_string()),
            version: None,
            info: Some("Application performance monitoring".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:newrelic:apm".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // Datadog Agent
    signatures.push(ServiceSignature {
        service_name: "datadog-agent".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Datadog Agent.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Datadog Agent".to_string()),
            version: Some("$1".to_string()),
            info: Some("Monitoring and analytics agent".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:datadog:datadog_agent:$1".to_string()],
        }),
        ports: vec![8125, 8126],
        protocol: "tcp".to_string(),
    });

    // Dynatrace OneAgent
    signatures.push(ServiceSignature {
        service_name: "dynatrace-agent".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Dynatrace".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Dynatrace OneAgent".to_string()),
            version: None,
            info: Some("Full-stack monitoring".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:dynatrace:oneagent".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // AppDynamics
    signatures.push(ServiceSignature {
        service_name: "appdynamics".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"AppDynamics".to_string(),
        version_info: Some(VersionInfo {
            product: Some("AppDynamics".to_string()),
            version: None,
            info: Some("Application performance management".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:appdynamics:appdynamics".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // ========== INFRASTRUCTURE MONITORING ==========

    // Nagios
    signatures.push(ServiceSignature {
        service_name: "nagios".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Nagios.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Nagios".to_string()),
            version: Some("$1".to_string()),
            info: Some("Infrastructure monitoring".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nagios:nagios:$1".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // Zabbix Server
    signatures.push(ServiceSignature {
        service_name: "zabbix-server".to_string(),
        probe_name: "Zabbix".to_string(),
        pattern: r"ZBXD".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Zabbix Server".to_string()),
            version: None,
            info: Some("Enterprise monitoring".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:zabbix:zabbix".to_string()],
        }),
        ports: vec![10051],
        protocol: "tcp".to_string(),
    });

    // Zabbix Agent
    signatures.push(ServiceSignature {
        service_name: "zabbix-agent".to_string(),
        probe_name: "Zabbix".to_string(),
        pattern: r"ZBXD".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Zabbix Agent".to_string()),
            version: None,
            info: Some("Monitoring agent".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:zabbix:zabbix".to_string()],
        }),
        ports: vec![10050],
        protocol: "tcp".to_string(),
    });

    // Icinga2
    signatures.push(ServiceSignature {
        service_name: "icinga2".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Icinga.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Icinga2".to_string()),
            version: Some("$1".to_string()),
            info: Some("Network monitoring".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:icinga:icinga2:$1".to_string()],
        }),
        ports: vec![5665],
        protocol: "tcp".to_string(),
    });

    // Sensu
    signatures.push(ServiceSignature {
        service_name: "sensu".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Sensu.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Sensu".to_string()),
            version: Some("$1".to_string()),
            info: Some("Monitoring event pipeline".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:sensu:sensu:$1".to_string()],
        }),
        ports: vec![3000, 8080],
        protocol: "tcp".to_string(),
    });

    // ========== REAL-TIME MONITORING ==========

    // Netdata
    signatures.push(ServiceSignature {
        service_name: "netdata".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"netdata.*([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Netdata".to_string()),
            version: Some("$1".to_string()),
            info: Some("Real-time performance monitoring".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:netdata:netdata:$1".to_string()],
        }),
        ports: vec![19999],
        protocol: "tcp".to_string(),
    });

    // Collectd
    signatures.push(ServiceSignature {
        service_name: "collectd".to_string(),
        probe_name: "Collectd".to_string(),
        pattern: r"collectd".to_string(),
        version_info: Some(VersionInfo {
            product: Some("collectd".to_string()),
            version: None,
            info: Some("System statistics collection daemon".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:collectd:collectd".to_string()],
        }),
        ports: vec![25826],
        protocol: "udp".to_string(),
    });

    // StatsD
    signatures.push(ServiceSignature {
        service_name: "statsd".to_string(),
        probe_name: "StatsD".to_string(),
        pattern: r"statsd".to_string(),
        version_info: Some(VersionInfo {
            product: Some("StatsD".to_string()),
            version: None,
            info: Some("Network daemon for statistics".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:etsy:statsd".to_string()],
        }),
        ports: vec![8125],
        protocol: "udp".to_string(),
    });

    // Carbon (Graphite)
    signatures.push(ServiceSignature {
        service_name: "carbon".to_string(),
        probe_name: "Carbon".to_string(),
        pattern: r"carbon".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Graphite Carbon".to_string()),
            version: None,
            info: Some("Metrics storage backend".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:graphite:carbon".to_string()],
        }),
        ports: vec![2003, 2004],
        protocol: "tcp".to_string(),
    });

    // Graphite Web
    signatures.push(ServiceSignature {
        service_name: "graphite-web".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Graphite".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Graphite Web".to_string()),
            version: None,
            info: Some("Metrics dashboard".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:graphite:graphite".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    signatures
}
