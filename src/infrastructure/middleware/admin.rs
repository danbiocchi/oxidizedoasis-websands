use actix_web::error::ResponseError;
use actix_web::{dev::ServiceRequest, Error, HttpMessage, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde_json::json;
use std::fmt;
use log::{error, debug};
use crate::core::auth::jwt::{validate_jwt, Claims};

#[derive(Debug)]
pub struct AdminError {
    pub message: String,
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl ResponseError for AdminError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Forbidden().json(json!({
            "error": "Forbidden",
            "message": self.message
        }))
    }
}

pub async fn admin_validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    debug!("Admin validator called for path: {}", req.path());
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = credentials.token();

    debug!("Attempting to validate token for admin access");

    match validate_jwt(token, &jwt_secret) {
        Ok(claims) => {
            if claims.role != "admin" {
                error!("Access denied: User role is not admin");
                return Err((AdminError {
                    message: "Access denied: Insufficient privileges".to_string()
                }.into(), req));
            }
            
            debug!("Admin access granted for user: {}", claims.sub);
            // Add claims to request extensions for use in handlers
            req.extensions_mut().insert(claims);
            Ok(req)
        },
        Err(e) => {
            error!("Token validation failed: {:?}", e);
            Err((AdminError {
                message: "Invalid or expired token".to_string()
            }.into(), req))
        },
    }
}