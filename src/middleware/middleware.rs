use actix_web::error::ResponseError;
use actix_web::{dev::ServiceRequest, Error, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use crate::auth;
use log::{error, debug, info};
use serde_json::json;
use std::fmt;  // Add this import

#[derive(Debug)]
pub struct ApiError {
    pub message: String,
}

impl fmt::Display for ApiError {  // Implement Display trait
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Unauthorized().json(json!({
            "error": "Unauthorized",
            "message": self.message
        }))
    }
}

/// Middleware function to validate JWT tokens
///
/// # Arguments
/// * `req` - The incoming service request
/// * `credentials` - The bearer authentication credentials
///
/// # Returns
/// * `Result<ServiceRequest, (Error, ServiceRequest)>` - Ok if token is valid, Err otherwise
pub async fn validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = credentials.token();

    debug!("Received request with token: {}", token);

    match auth::validate_jwt(token, &jwt_secret) {
        Ok(claims) => {
            info!("Token validated successfully for user: {}", claims.sub);
            Ok(req)
        },
        Err(e) => {
            error!("Token validation failed. Token: {}. Error: {:?}", token, e);
            Err((ApiError { message: "Invalid token".to_string() }.into(), req))
        },
    }
}
