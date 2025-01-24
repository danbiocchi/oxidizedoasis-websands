use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::core::user::{User, UserRepository};
use crate::common::error::ApiError;

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    role: String,
}

#[derive(Deserialize)]
pub struct UpdateStatusRequest {
    is_active: bool,
}

#[derive(Serialize)]
pub struct UserListResponse {
    users: Vec<UserAdminView>,
    total: i64,
    page: i32,
    per_page: i32,
}

#[derive(Serialize)]
pub struct UserAdminView {
    id: Uuid,
    username: String,
    email: Option<String>,
    role: String,
    is_email_verified: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<User> for UserAdminView {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            is_email_verified: user.is_email_verified,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[derive(Deserialize)]
pub struct UserListQuery {
    page: Option<i32>,
    per_page: Option<i32>,
    role: Option<String>,
    search: Option<String>,
}

pub async fn list_users(
    query: web::Query<UserListQuery>,
    repo: web::Data<UserRepository>,
) -> Result<HttpResponse, ApiError> {
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(10).min(100);
    let offset = (page - 1) * per_page;

    let users = repo.find_all_paginated(offset, per_page, query.role.as_deref(), query.search.as_deref())
        .await
        .map_err(ApiError::from)?;

    let total = repo.count_all(query.role.as_deref(), query.search.as_deref())
        .await
        .map_err(ApiError::from)?;

    let response = UserListResponse {
        users: users.into_iter().map(UserAdminView::from).collect(),
        total,
        page,
        per_page,
    };

    Ok(HttpResponse::Ok().json(response))
}

pub async fn get_user(
    id: web::Path<Uuid>,
    repo: web::Data<UserRepository>,
) -> Result<HttpResponse, ApiError> {
    let user = repo.find_by_id(*id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    Ok(HttpResponse::Ok().json(UserAdminView::from(user)))
}

pub async fn update_user_role(
    id: web::Path<Uuid>,
    req: web::Json<UpdateRoleRequest>,
    repo: web::Data<UserRepository>,
) -> Result<HttpResponse, ApiError> {
    // Validate role
    if !["user", "admin"].contains(&req.role.as_str()) {
        return Err(ApiError::bad_request("Invalid role"));
    }

    let user = repo.update_role(*id, &req.role)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    Ok(HttpResponse::Ok().json(UserAdminView::from(user)))
}

pub async fn update_user_status(
    id: web::Path<Uuid>,
    req: web::Json<UpdateStatusRequest>,
    repo: web::Data<UserRepository>,
) -> Result<HttpResponse, ApiError> {
    let user = repo.update_status(*id, req.is_active)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    Ok(HttpResponse::Ok().json(UserAdminView::from(user)))
}