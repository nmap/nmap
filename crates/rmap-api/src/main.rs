mod middleware;
mod models;
mod routes;
mod services;
mod websocket;

use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post},
    Router,
};
use axum::http::{header, Method, HeaderValue};
use axum_prometheus::PrometheusMetricLayer;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use middleware::{auth_middleware, api_rate_limiter, scan_rate_limiter, websocket_rate_limiter};
use routes::{
    create_scan, delete_scan, get_scan, get_scan_hosts, get_scan_vulnerabilities,
    list_scans, start_scan, get_host, login, register
};
use services::{EventBus, ScanService};
use websocket::ws_handler;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| format!("Failed to set subscriber: {}", e))?;

    info!("Starting R-Map API Server");

    // Check for JWT_SECRET environment variable
    if std::env::var("JWT_SECRET").is_err() {
        warn!("⚠️  JWT_SECRET not set! Using default secret (INSECURE for production)");
        warn!("⚠️  Set JWT_SECRET environment variable for production use");
    }

    // Initialize services
    let scan_service = Arc::new(ScanService::new());
    let event_bus = Arc::new(EventBus::new());

    // Initialize Prometheus metrics (2025 best practice: separate metrics server)
    let (prometheus_layer, metric_handle) = PrometheusMetricLayer::pair();
    info!("✓ Prometheus metrics initialized");

    // Configure CORS - SECURE configuration for Svelte frontend
    // Note: These are static URLs so parse() should never fail, but we handle errors properly
    let origin_3000 = "http://localhost:3000".parse::<HeaderValue>()
        .map_err(|e| format!("Invalid CORS origin http://localhost:3000: {}", e))?;
    let origin_5173 = "http://localhost:5173".parse::<HeaderValue>()
        .map_err(|e| format!("Invalid CORS origin http://localhost:5173: {}", e))?;
    let origin_127_3000 = "http://127.0.0.1:3000".parse::<HeaderValue>()
        .map_err(|e| format!("Invalid CORS origin http://127.0.0.1:3000: {}", e))?;
    let origin_127_5173 = "http://127.0.0.1:5173".parse::<HeaderValue>()
        .map_err(|e| format!("Invalid CORS origin http://127.0.0.1:5173: {}", e))?;

    let cors = CorsLayer::new()
        .allow_origin(origin_3000)
        .allow_origin(origin_5173) // Vite/Svelte dev server
        .allow_origin(origin_127_3000)
        .allow_origin(origin_127_5173)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PUT, Method::PATCH])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true);

    // Build public routes (no authentication required)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/register", post(register));

    // Build protected routes (authentication required)
    let protected_routes = Router::new()
        // Scan routes (with strict rate limiting for creation)
        .route("/api/v1/scans", post(create_scan).layer(scan_rate_limiter()))
        .route("/api/v1/scans", get(list_scans))
        .route("/api/v1/scans/:id", get(get_scan))
        .route("/api/v1/scans/:id", delete(delete_scan))
        .route("/api/v1/scans/:id/start", post(start_scan).layer(scan_rate_limiter()))
        // Host routes
        .route("/api/v1/scans/:id/hosts", get(get_scan_hosts))
        .route("/api/v1/hosts/:id", get(get_host))
        // Vulnerability routes
        .route("/api/v1/scans/:id/vulnerabilities", get(get_scan_vulnerabilities))
        // Apply authentication middleware to all protected routes
        .layer(axum_middleware::from_fn(auth_middleware))
        // Apply general API rate limiting
        .layer(api_rate_limiter());

    // WebSocket route (separate rate limiting)
    let websocket_routes = Router::new()
        .route("/ws", get(ws_handler))
        .layer(axum_middleware::from_fn(auth_middleware))
        .layer(websocket_rate_limiter());

    // Combine all routes with Prometheus metrics
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(websocket_routes)
        .with_state(scan_service.clone())
        .with_state(event_bus.clone())
        .layer(prometheus_layer)  // Track all requests
        .layer(cors);

    // Create separate metrics server (port 3001, internal only)
    let metrics_app = Router::new()
        .route("/metrics", get(|| async move { metric_handle.render() }))
        .route("/health", get(|| async { "Metrics OK" }));

    // Spawn metrics server on separate port (best practice: not publicly exposed)
    let metrics_listener = tokio::net::TcpListener::bind("0.0.0.0:3001")
        .await
        .map_err(|e| format!("Failed to bind metrics server to port 3001: {}", e))?;

    tokio::spawn(async move {
        info!("📊 Metrics server listening on http://0.0.0.0:3001/metrics");
        if let Err(e) = axum::serve(metrics_listener, metrics_app).await {
            warn!("Metrics server error: {}", e);
        }
    });

    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .map_err(|e| format!("Failed to bind to port 8080: {}. Port may already be in use or insufficient privileges", e))?;

    info!("🚀 R-Map API Server listening on http://0.0.0.0:8080");
    info!("");
    info!("📋 Available Endpoints:");
    info!("  Public:");
    info!("    GET  /health                              - Health check");
    info!("    POST /api/v1/auth/login                   - Login (get JWT token)");
    info!("    POST /api/v1/auth/register                - Register (demo only)");
    info!("");
    info!("  Protected (requires Authorization: Bearer <token>):");
    info!("    POST   /api/v1/scans                      - Create scan (2 req/min)");
    info!("    GET    /api/v1/scans                      - List scans");
    info!("    GET    /api/v1/scans/:id                  - Get scan details");
    info!("    DELETE /api/v1/scans/:id                  - Delete scan");
    info!("    POST   /api/v1/scans/:id/start            - Start scan (2 req/min)");
    info!("    GET    /api/v1/scans/:id/hosts            - Get scan hosts");
    info!("    GET    /api/v1/hosts/:id                  - Get host details");
    info!("    GET    /api/v1/scans/:id/vulnerabilities  - Get vulnerabilities");
    info!("    WS     /ws                                - WebSocket (5 conn/min)");
    info!("");
    info!("📊 Metrics (Internal Only):");
    info!("    GET  http://localhost:3001/metrics        - Prometheus metrics");
    info!("    GET  http://localhost:3001/health         - Metrics health check");
    info!("");
    info!("🔒 Security Features:");
    info!("  ✓ JWT Authentication (required for all scans)");
    info!("  ✓ Rate Limiting (10 req/min general, 2 req/min scans)");
    info!("  ✓ CORS (localhost:3000, localhost:5173)");
    info!("  ✓ Prometheus metrics tracking");
    info!("");
    info!("🔑 Default Credentials:");
    info!("  Username: admin");
    info!("  Password: admin");
    info!("  (Change via API_USERNAME and API_PASSWORD_HASH env vars)");

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("Server failed: {}", e))?;

    Ok(())
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}
