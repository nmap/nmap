mod models;
mod routes;
mod services;
mod websocket;

use axum::{
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use routes::{create_scan, delete_scan, get_scan, get_scan_hosts, get_scan_vulnerabilities, list_scans, start_scan, get_host};
use services::{EventBus, ScanService};
use websocket::ws_handler;

#[tokio::main]
async fn main() {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    info!("Starting R-Map API Server");

    // Initialize services
    let scan_service = Arc::new(ScanService::new());
    let event_bus = Arc::new(EventBus::new());

    // Configure CORS for Svelte frontend
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build router
    let app = Router::new()
        // Scan routes
        .route("/api/v1/scans", post(create_scan))
        .route("/api/v1/scans", get(list_scans))
        .route("/api/v1/scans/:id", get(get_scan))
        .route("/api/v1/scans/:id", delete(delete_scan))
        .route("/api/v1/scans/:id/start", post(start_scan))
        // Host routes
        .route("/api/v1/scans/:id/hosts", get(get_scan_hosts))
        .route("/api/v1/hosts/:id", get(get_host))
        // Vulnerability routes
        .route("/api/v1/scans/:id/vulnerabilities", get(get_scan_vulnerabilities))
        // WebSocket
        .route("/ws", get(ws_handler))
        // Health check
        .route("/health", get(health_check))
        // State
        .with_state(scan_service.clone())
        .with_state(event_bus.clone())
        .layer(cors);

    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("Failed to bind to port 8080");

    info!("Server listening on http://0.0.0.0:8080");
    info!("WebSocket endpoint: ws://0.0.0.0:8080/ws");
    info!("API documentation: http://0.0.0.0:8080/api/v1/scans");

    axum::serve(listener, app)
        .await
        .expect("Server failed");
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}
