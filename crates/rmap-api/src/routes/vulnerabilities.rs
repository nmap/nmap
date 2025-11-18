use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use uuid::Uuid;
use std::sync::Arc;

use crate::{
    models::{ListVulnerabilitiesResponse, SeverityCounts},
    services::ScanService,
};

/// GET /api/v1/scans/:id/vulnerabilities - Get all vulnerabilities for a scan
pub async fn get_scan_vulnerabilities(
    State(service): State<Arc<ScanService>>,
    Path(scan_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let vulnerabilities = service
        .get_scan_vulnerabilities(scan_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut by_severity = SeverityCounts::default();
    for vuln in &vulnerabilities {
        by_severity.add(&vuln.severity);
    }

    let total = vulnerabilities.len();

    Ok(Json(ListVulnerabilitiesResponse {
        vulnerabilities,
        total,
        by_severity,
    }))
}
