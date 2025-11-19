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

    // ========== ASP.NET & .NET SERVERS ==========

    // Kestrel (ASP.NET Core)
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Kestrel".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Kestrel".to_string()),
            version: None,
            info: Some("ASP.NET Core web server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:microsoft:kestrel".to_string()],
        }),
        ports: vec![5000, 5001, 80, 443],
        protocol: "tcp".to_string(),
    });

    // ========== RUBY SERVERS ==========

    // WEBrick
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: WEBrick/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("WEBrick".to_string()),
            version: Some("$1".to_string()),
            info: Some("Ruby HTTP server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:ruby-lang:webrick:$1".to_string()],
        }),
        ports: vec![3000, 8080],
        protocol: "tcp".to_string(),
    });

    // Puma
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Puma ([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Puma".to_string()),
            version: Some("$1".to_string()),
            info: Some("Ruby web server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:puma:puma:$1".to_string()],
        }),
        ports: vec![3000, 9292],
        protocol: "tcp".to_string(),
    });

    // Unicorn
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Unicorn ([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Unicorn".to_string()),
            version: Some("$1".to_string()),
            info: Some("Ruby HTTP server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:unicorn:unicorn:$1".to_string()],
        }),
        ports: vec![8080, 8000],
        protocol: "tcp".to_string(),
    });

    // Passenger (Phusion Passenger)
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: nginx/.*Phusion Passenger|X-Powered-By: Phusion Passenger".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Phusion Passenger".to_string()),
            version: None,
            info: Some("Application server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:phusion:passenger".to_string()],
        }),
        ports: vec![80, 443],
        protocol: "tcp".to_string(),
    });

    // ========== SPECIALIZED NGINX ==========

    // OpenResty (Nginx + Lua)
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: openresty/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OpenResty".to_string()),
            version: Some("$1".to_string()),
            info: Some("Nginx + Lua".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:openresty:openresty:$1".to_string()],
        }),
        ports: vec![80, 443, 8080],
        protocol: "tcp".to_string(),
    });

    // ========== LIGHTWEIGHT SERVERS ==========

    // Cherokee
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Cherokee/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Cherokee".to_string()),
            version: Some("$1".to_string()),
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:cherokee-project:cherokee:$1".to_string()],
        }),
        ports: vec![80, 443],
        protocol: "tcp".to_string(),
    });

    // Mongoose
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Mongoose/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Mongoose".to_string()),
            version: Some("$1".to_string()),
            info: Some("Embedded web server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:cesanta:mongoose:$1".to_string()],
        }),
        ports: vec![8000, 8080],
        protocol: "tcp".to_string(),
    });

    // ========== PYTHON SERVERS ==========

    // Tornado
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: TornadoServer/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Tornado".to_string()),
            version: Some("$1".to_string()),
            info: Some("Python web framework".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:tornadoweb:tornado:$1".to_string()],
        }),
        ports: vec![8000, 8888],
        protocol: "tcp".to_string(),
    });

    // Twisted Web
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: TwistedWeb/([0-9.]+)".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Twisted Web".to_string()),
            version: Some("$1".to_string()),
            info: Some("Python networking engine".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:twistedmatrix:twisted:$1".to_string()],
        }),
        ports: vec![8080, 8000],
        protocol: "tcp".to_string(),
    });

    // ========== JVM SERVERS ==========

    // Vert.x
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Vert\.x|X-Powered-By: Vert\.x".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Vert.x".to_string()),
            version: None,
            info: Some("JVM toolkit".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:eclipse:vert.x".to_string()],
        }),
        ports: vec![8080, 8443],
        protocol: "tcp".to_string(),
    });

    // Undertow (JBoss)
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Undertow".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Undertow".to_string()),
            version: None,
            info: Some("JBoss web server".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:redhat:undertow".to_string()],
        }),
        ports: vec![8080, 8443],
        protocol: "tcp".to_string(),
    });

    // Netty
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Netty|X-Powered-By: Netty".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Netty".to_string()),
            version: None,
            info: Some("Java network framework".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:netty:netty".to_string()],
        }),
        ports: vec![8080, 8000],
        protocol: "tcp".to_string(),
    });

    // ========== MODERN SERVERS ==========

    // Golang net/http
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: Go-http-server|X-Powered-By: Go".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Go http server".to_string()),
            version: None,
            info: Some("Golang net/http".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:golang:http".to_string()],
        }),
        ports: vec![8080, 8000, 3000],
        protocol: "tcp".to_string(),
    });

    // Deno Deploy
    signatures.push(ServiceSignature {
        service_name: "http".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Server: deno|x-deno-deployment-id".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Deno".to_string()),
            version: None,
            info: Some("JavaScript/TypeScript runtime".to_string()),
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:deno:deno".to_string()],
        }),
        ports: vec![8000, 8080],
        protocol: "tcp".to_string(),
    });

    signatures
}
