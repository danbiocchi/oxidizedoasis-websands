use actix_web::error::ResponseError;
use actix_web::{dev::ServiceRequest, Error, HttpMessage, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde_json::json;
use std::fmt;
use log::{error, debug, info};
use crate::core::auth::validate_jwt;

#[derive(Debug)]
pub struct AuthError {
    pub message: String,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Unauthorized().json(json!({
            "error": "Unauthorized",
            "message": self.message
        }))
    }
}

pub async fn validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = credentials.token();

    debug!("Validating JWT token");

    match validate_jwt(token, &jwt_secret) {
        Ok(claims) => {
            info!("Token validated successfully for user: {}", claims.sub);
            // Add claims to request extensions for use in handlers
            req.extensions_mut().insert(claims);
            Ok(req)
        },
        Err(e) => {
            error!("Token validation failed: {:?}", e);
            Err((AuthError {
                message: "Invalid or expired token".to_string()
            }.into(), req))
        },
    }
}