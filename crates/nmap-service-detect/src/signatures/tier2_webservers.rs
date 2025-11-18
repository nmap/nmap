use crate::signatures::{ServiceSignature, VersionInfo};

/// Tier 2 Web Servers - Specific web server implementations
/// Loaded after tier1 common services
pub fn load_tier2_webserver_signatures() -> Vec<ServiceSignature> {
    let mut signatures = Vec::new();

    // ========== WEB SERVERS ==========

    // Apache HTTP Server
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Apache/([0-9.]+)(?:\s+\(([^)]+)\))?".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache httpd".to_string()),
            version: Some("$1".to_string()),
            info: Some("$2".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:http_server:$1".to_string()],
        }),
        ports: vec![80, 8080, 443, 8443],
        protocol: "tcp".to_string(),
    });

    // Nginx
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: nginx/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("nginx".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nginx:nginx:$1".to_string()],
        }),
        ports: vec![80, 8080, 443, 8443],
        protocol: "tcp".to_string(),
    });

    // Microsoft IIS
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Microsoft-IIS/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Microsoft IIS httpd".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: Some("Windows".to_string()),
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:iis:$1".to_string()],
        }),
        ports: vec![80, 8080, 443],
        protocol: "tcp".to_string(),
    });

    // Apache Tomcat
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Apache-Coyote/([0-9.]+)|Apache Tomcat/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Apache Tomcat".to_string()),
            version: Some("$1$2".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:apache:tomcat:$1$2".to_string()],
        }),
        ports: vec![8080, 8009, 8443],
        protocol: "tcp".to_string(),
    });

    // Jetty
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Jetty\(([0-9.]+[^)]*)\)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Jetty".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:eclipse:jetty:$1".to_string()],
        }),
        ports: vec![8080, 8443],
        protocol: "tcp".to_string(),
    });

    // Lighttpd
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: lighttpd/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("lighttpd".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:lighttpd:lighttpd:$1".to_string()],
        }),
        ports: vec![80, 8080, 443],
        protocol: "tcp".to_string(),
    });

    // Node.js
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"X-Powered-By: Express|Node\.js".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Node.js".to_string()),
            version: None,
            info: Some("Express framework".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:nodejs:node.js".to_string()],
        }),
        ports: vec![3000, 8080, 8000],
        protocol: "tcp".to_string(),
    });

    // Gunicorn
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: gunicorn/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Gunicorn".to_string()),
            version: Some("$1".to_string()),
            info: Some("Python WSGI HTTP Server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:gunicorn:gunicorn:$1".to_string()],
        }),
        ports: vec![8000, 8080],
        protocol: "tcp".to_string(),
    });

    // Caddy
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Caddy|caddy".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Caddy".to_string()),
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:caddyserver:caddy".to_string()],
        }),
        ports: vec![80, 443, 2015],
        protocol: "tcp".to_string(),
    });

    // Uvicorn (Python ASGI server)
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: uvicorn".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Uvicorn".to_string()),
            version: None,
            info: Some("ASGI server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:uvicorn:uvicorn".to_string()],
        }),
        ports: vec![8000, 8080],
        protocol: "tcp".to_string(),
    });

    signatures
}
