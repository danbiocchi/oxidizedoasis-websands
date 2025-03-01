use actix_web::error::ResponseError;
use actix_web::{dev::ServiceRequest, Error, HttpMessage, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde_json::json;
use std::fmt;
use log::{error, debug, warn};
use crate::core::auth::jwt::{validate_jwt, Claims, TokenType};

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

    // Validate as an access token - we don't accept refresh tokens for API access
    let validation_result = validate_jwt(token, &jwt_secret, Some(TokenType::Access)).await;
    
    match validation_result {
        Ok(claims) => {
            // Check if the user has admin role
            if claims.role != "admin" {
                error!("Access denied: User {} with role {} attempted to access admin endpoint", 
                       claims.sub, claims.role);
                return Err((AdminError {
                    message: "Access denied: Insufficient privileges".to_string()
                }.into(), req));
            }
            
            // Check token expiration time and warn if it's close to expiring
            let now = chrono::Utc::now().timestamp();
            let remaining_time = claims.exp - now;
            
            if remaining_time < 300 { // Less than 5 minutes remaining
                warn!("Admin token for user {} is about to expire in {} seconds", claims.sub, remaining_time);
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