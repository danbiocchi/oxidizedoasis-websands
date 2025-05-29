use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::common::error::ApiError;

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    InProgress,
    Resolved,
    Closed,
}

#[derive(Serialize)]
pub struct SecurityIncident {
    id: Uuid,
    title: String,
    description: String,
    severity: IncidentSeverity,
    status: IncidentStatus,
    reported_by: Uuid,
    assigned_to: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
    resolution_notes: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateIncidentRequest {
    title: String,
    description: String,
    severity: IncidentSeverity,
    assigned_to: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct UpdateIncidentStatusRequest {
    status: IncidentStatus,
    resolution_notes: Option<String>,
}

#[derive(Deserialize)]
pub struct IncidentListQuery {
    severity: Option<IncidentSeverity>,
    status: Option<IncidentStatus>,
    start_date: Option<DateTime<Utc>>,
    end_date: Option<DateTime<Utc>>,
    page: Option<i32>,
    per_page: Option<i32>,
}

#[derive(Serialize)]
pub struct IncidentListResponse {
    incidents: Vec<SecurityIncident>,
    total: i64,
    page: i32,
    per_page: i32,
}

pub async fn list_incidents(
    query: web::Query<IncidentListQuery>,
) -> Result<HttpResponse, ApiError> {
    // TODO: Implement actual incident retrieval from database
    // This is a placeholder that returns an empty response
    let page = query.page.unwrap_or(1);
    if page < 1 {
        return Err(ApiError::bad_request("Page number must be positive"));
    }

    let per_page = query.per_page.unwrap_or(20); // Default from current code
    if per_page < 1 {
        return Err(ApiError::bad_request("Per page count must be positive"));
    }
    let per_page = per_page.min(100); // Apply max limit

    let response = IncidentListResponse {
        incidents: Vec::new(),
        total: 0,
        page,
        per_page,
    };

    Ok(HttpResponse::Ok().json(response))
}

pub async fn create_incident(
    req: web::Json<CreateIncidentRequest>,
    claims: web::ReqData<crate::core::auth::jwt::Claims>,
) -> Result<HttpResponse, ApiError> {
    // Validate request
    if req.title.trim().len() < 5 {
        return Err(ApiError::bad_request("Title must be at least 5 characters long"));
    }
    if req.title.len() > 255 {
        return Err(ApiError::bad_request("Title cannot exceed 255 characters"));
    }
    if req.description.trim().len() < 10 {
        return Err(ApiError::bad_request("Description must be at least 10 characters long"));
    }

    // TODO: Validate if req.assigned_to (if Some) corresponds to a valid user ID.
    // TODO: Implement actual incident creation in database
    // This is a placeholder that returns a mock incident
    let incident = SecurityIncident {
        id: Uuid::new_v4(),
        title: req.title.clone(),
        description: req.description.clone(),
        severity: req.severity.clone(),
        status: IncidentStatus::Open,
        reported_by: claims.into_inner().sub,
        assigned_to: req.assigned_to,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        resolution_notes: None,
    };

    Ok(HttpResponse::Created().json(incident))
}

pub async fn get_incident(
    id: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    // TODO: Implement actual incident retrieval from database
    // This is a placeholder that returns a not found error
    Err(ApiError::not_found("Incident not found"))
}

pub async fn update_incident_status(
    id: web::Path<Uuid>,
    req: web::Json<UpdateIncidentStatusRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate request based on status
    if req.status == IncidentStatus::Resolved || req.status == IncidentStatus::Closed {
        if let Some(notes) = &req.resolution_notes {
            if notes.trim().len() < 10 {
                return Err(ApiError::bad_request("Resolution notes must be at least 10 characters long when status is Resolved or Closed"));
            }
        } else {
            return Err(ApiError::bad_request("Resolution notes are required when setting status to Resolved or Closed"));
        }
    }

    // TODO: Implement actual incident status update in database
    // This is a placeholder that returns a not found error
    Err(ApiError::not_found("Incident not found"))
}