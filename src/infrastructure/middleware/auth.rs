use crate::core::auth::jwt::{validate_jwt, TokenType};
use actix_web::error::ResponseError;
use actix_web::{dev::ServiceRequest, Error, HttpMessage, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde_json::json;
use std::fmt;
use log::{error, debug, info, warn};


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

pub async fn jwt_auth_validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = credentials.token();

    debug!("Validating JWT token");

    // Validate as an access token - we don't accept refresh tokens for API access
    let validation_result = validate_jwt(token, &jwt_secret, Some(TokenType::Access)).await;
    
    match validation_result {
        Ok(claims) => {
            info!("Token validated successfully for user: {}", claims.sub);
            
            // Check token expiration time and warn if it's close to expiring
            let now = chrono::Utc::now().timestamp();
            let remaining_time = claims.exp - now;
            
            if remaining_time < 300 { // Less than 5 minutes remaining
                warn!("Token for user {} is about to expire in {} seconds", claims.sub, remaining_time);
            }
            
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
