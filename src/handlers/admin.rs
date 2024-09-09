use actix_web::error::ErrorUnauthorized;
use actix_web::{dev::ServiceRequest, Error, web, HttpResponse, Responder};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use sqlx::PgPool;
use crate::auth;
use log::{error, info};
use chrono; // Import chrono for DateTime
use uuid::Uuid; // Import Uuid for User struct
use std::sync::Arc;
use crate::email::EmailServiceTrait;

#[derive(serde::Serialize)]
struct User {
    id: Uuid,
    username: Option<String>,
    email: Option<String>,
    role: Option<String>,
    is_email_verified: bool,
    created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn admin_validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = credentials.token();
    let pool = req.app_data::<web::Data<PgPool>>().unwrap();

    match auth::validate_jwt(token, &jwt_secret) {
        Ok(claims) => {
            let user = sqlx::query!("SELECT role FROM users WHERE id = $1", claims.sub)
                .fetch_optional(pool.get_ref())
                .await;

            match user {
                Ok(Some(user)) if user.role == "admin" => {
                    info!("Admin access granted for user: {}", claims.sub);
                    Ok(req)
                },
                _ => {
                    error!("Admin access denied for user: {}", claims.sub);
                    Err((ErrorUnauthorized("Admin access required"), req))
                }
            }
        },
        Err(e) => {
            error!("Token validation failed. Error: {:?}", e);
            Err((ErrorUnauthorized("Invalid token"), req))
        },
    }
}

pub async fn admin_dashboard(pool: web::Data<PgPool>) -> HttpResponse {
    let users = sqlx::query_as!(
        User,
        r#"SELECT id, username, email, role, is_email_verified, created_at FROM users"#
    )
    .fetch_all(pool.get_ref())
    .await;

    match users {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[allow(dead_code)]
pub async fn admin_function(
    // ... other parameters
    _email_service: web::Data<Arc<dyn EmailServiceTrait>>,
) -> impl Responder {
    // Function implementation
    HttpResponse::Ok().finish()
}