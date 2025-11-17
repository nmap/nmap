use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use uuid::Uuid;
use std::sync::Arc;

use crate::{
    models::{CreateScanRequest, CreateScanResponse, ListScansResponse, Scan, ScanSummary},
    services::ScanService,
};

/// POST /api/v1/scans - Create a new scan
pub async fn create_scan(
    State(service): State<Arc<ScanService>>,
    Json(request): Json<CreateScanRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Validate targets
    if request.targets.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "At least one target is required".to_string(),
        ));
    }

    // Create the scan
    let scan = service
        .create_scan(request.targets, request.options)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response = CreateScanResponse {
        scan_id: scan.id,
        status: scan.status.clone(),
        created_at: scan.created_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/v1/scans - List all scans
pub async fn list_scans(
    State(service): State<Arc<ScanService>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scans = service
        .list_scans()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let summaries: Vec<ScanSummary> = scans.iter().map(ScanSummary::from).collect();
    let total = summaries.len();

    Ok(Json(ListScansResponse {
        scans: summaries,
        total,
    }))
}

/// GET /api/v1/scans/:id - Get specific scan details
pub async fn get_scan(
    State(service): State<Arc<ScanService>>,
    Path(scan_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scan = service
        .get_scan(scan_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Scan not found".to_string()))?;

    Ok(Json(scan))
}

/// DELETE /api/v1/scans/:id - Cancel a scan
pub async fn delete_scan(
    State(service): State<Arc<ScanService>>,
    Path(scan_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    service
        .cancel_scan(scan_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/scans/:id/start - Start a pending scan
pub async fn start_scan(
    State(service): State<Arc<ScanService>>,
    Path(scan_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    service
        .start_scan(scan_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::ACCEPTED)
}
