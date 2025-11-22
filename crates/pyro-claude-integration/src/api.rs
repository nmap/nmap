//! REST API and WebSocket server (replaces rethinkdb/redis architecture)
//!
//! Built with Axum, using redb for all persistence and real-time updates.

use crate::database::PyroDatabase;
use crate::events::{EventBus, EventStream};
use crate::claude_agent::ClaudeAgent;
use crate::fire_marshal::{FireMarshal, CreateInvestigationRequest};
use axum::{
    extract::{Path, State, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, delete},
    Json, Router,
};
use axum::extract::ws::{WebSocket, Message};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::{CorsLayer, Any};
use uuid::Uuid;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<PyroDatabase>,
    pub event_bus: Arc<EventBus>,
    pub claude_agent: Arc<ClaudeAgent>,
    pub fire_marshal: Arc<FireMarshal>,
}

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Health check
        .route("/health", get(health_check))

        // Fire Marshal investigations
        .route("/api/v1/investigations", post(create_investigation))
        .route("/api/v1/investigations", get(list_investigations))
        .route("/api/v1/investigations/:id", get(get_investigation))
        .route("/api/v1/investigations/:id/close", post(close_investigation))
        .route("/api/v1/investigations/:id/evidence", post(add_evidence))
        .route("/api/v1/investigations/:id/detonator", post(trigger_detonator))

        // Claude workflows
        .route("/api/v1/workflows/start", post(start_workflow))
        .route("/api/v1/workflows/:id/status", get(get_workflow_status))
        .route("/api/v1/workflows/analyze", post(analyze_scan))

        // R-Map scans (already in rmap-api, but integrated here)
        .route("/api/v1/scans/:id", get(get_scan))

        // WebSocket for real-time events
        .route("/ws", get(websocket_handler))

        // CORS
        .layer(CorsLayer::new().allow_origin(Any))

        .with_state(state)
}

// Handlers

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({"status": "healthy"}))
}

async fn create_investigation(
    State(state): State<AppState>,
    Json(req): Json<CreateInvestigationRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let investigation = state.fire_marshal.create_investigation(req).await?;
    Ok(Json(serde_json::to_value(&investigation)?))
}

async fn list_investigations(
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let investigations = state.fire_marshal.list_investigations(50)?;
    let json: Vec<_> = investigations.iter()
        .map(|i| serde_json::to_value(i).unwrap())
        .collect();
    Ok(Json(json))
}

async fn get_investigation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let investigation = state.fire_marshal.get_investigation(&id)?;
    Ok(Json(serde_json::to_value(&investigation)?))
}

async fn close_investigation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<CloseInvestigationRequest>,
) -> Result<StatusCode, AppError> {
    state.fire_marshal.close_investigation(&id, req.findings, req.remediation).await?;
    Ok(StatusCode::OK)
}

async fn add_evidence(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<AddEvidenceRequest>,
) -> Result<StatusCode, AppError> {
    state.fire_marshal.add_evidence(&id, &req.scan_id).await?;
    Ok(StatusCode::OK)
}

async fn trigger_detonator(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<TriggerDetonatorRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = state.fire_marshal.trigger_detonator(&id, &req.detonator_name).await?;
    Ok(Json(serde_json::to_value(&result)?))
}

async fn start_workflow(
    State(state): State<AppState>,
    Json(req): Json<StartWorkflowRequest>,
) -> Result<Json<StartWorkflowResponse>, AppError> {
    let workflow = crate::claude_agent::ClaudeWorkflows::network_perimeter_assessment(req.target);
    let workflow_id = state.claude_agent.start_workflow(workflow, req.investigation_id).await?;

    Ok(Json(StartWorkflowResponse { workflow_id }))
}

async fn get_workflow_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let status = state.claude_agent.get_workflow_status(&id)?;
    Ok(Json(serde_json::to_value(&status)?))
}

async fn analyze_scan(
    State(state): State<AppState>,
    Json(req): Json<AnalyzeScanRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let analysis = state.claude_agent.analyze_scan_results(&req.scan_id).await?;
    Ok(Json(serde_json::to_value(&analysis)?))
}

async fn get_scan(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let scan = state.db.get_scan(&id)?;
    Ok(Json(serde_json::to_value(&scan)?))
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

async fn handle_websocket(mut socket: WebSocket, state: AppState) {
    let mut event_stream = EventStream::new(state.event_bus.subscribe());

    loop {
        tokio::select! {
            event_result = event_stream.recv() => {
                match event_result {
                    Ok(event) => {
                        let json = serde_json::to_string(&event).unwrap();
                        if socket.send(Message::Text(json)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

// Request/Response types

#[derive(Debug, Deserialize)]
struct CloseInvestigationRequest {
    findings: String,
    remediation: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AddEvidenceRequest {
    scan_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct TriggerDetonatorRequest {
    detonator_name: String,
}

#[derive(Debug, Deserialize)]
struct StartWorkflowRequest {
    target: String,
    investigation_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct StartWorkflowResponse {
    workflow_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct AnalyzeScanRequest {
    scan_id: Uuid,
}

// Error handling

#[derive(Debug)]
struct AppError(Box<dyn std::error::Error>);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": self.0.to_string()})),
        ).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<Box<dyn std::error::Error>>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
