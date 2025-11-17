use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use uuid::Uuid;
use std::sync::Arc;

use crate::{
    models::ListHostsResponse,
    services::ScanService,
};

/// GET /api/v1/scans/:id/hosts - Get all hosts for a scan
pub async fn get_scan_hosts(
    State(service): State<Arc<ScanService>>,
    Path(scan_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let hosts = service
        .get_scan_hosts(scan_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total = hosts.len();

    Ok(Json(ListHostsResponse { hosts, total }))
}

/// GET /api/v1/hosts/:id - Get specific host details
pub async fn get_host(
    State(service): State<Arc<ScanService>>,
    Path(host_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let host = service
        .get_host(host_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Host not found".to_string()))?;

    Ok(Json(host))
}
