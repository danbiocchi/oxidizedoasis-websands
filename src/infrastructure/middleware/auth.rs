use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    web::{self}, 
    Error, HttpMessage, HttpResponse,
};
use actix_web::error::ResponseError;
use actix_web::http::StatusCode;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use futures_util::future::{ready, Ready, LocalBoxFuture};
use log::{debug, error, info, warn};
use serde_json::json;
use std::fmt;
// Note: std::future::Future, std::pin::Pin, std::rc::Rc, std::task::{Context, Poll} are often implicitly used by LocalBoxFuture and other types.
// Explicit imports are kept if they were there, but might not be strictly necessary if types are fully qualified or brought in by other `use` statements.
 
 
use std::rc::Rc;
use std::sync::Arc; 
use std::task::{Context, Poll};

use crate::core::auth::jwt::{validate_jwt, TokenType};
use crate::core::auth::token_revocation::TokenRevocationServiceTrait;

#[derive(Debug)]
pub struct AuthError {
    pub message: String,
    pub status_code: StatusCode,
}

impl AuthError {
    pub fn new(message: String, status_code_u16: u16) -> Self {
        Self {
            message,
            status_code: StatusCode::from_u16(status_code_u16)
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Status {}: {}", self.status_code, self.message)
    }
}

impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        self.status_code
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let error_reason = status.canonical_reason().unwrap_or_else(|| {
            if status.is_client_error() { "Client Error" }
            else if status.is_server_error() { "Server Error" }
            else { "Error" }
        });
        HttpResponse::build(status).json(json!({
            "error": error_reason,
            "message": self.message
        }))
    }
}

pub async fn jwt_auth_validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    jwt_auth_validator_internal(req, Some(credentials)).await
}

pub async fn cookie_auth_validator(req: ServiceRequest) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    jwt_auth_validator_internal(req, None).await
}

async fn jwt_auth_validator_internal(
    req: ServiceRequest, credentials: Option<BearerAuth>) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let token_revocation_service_data = req.app_data::<web::Data<Arc<dyn TokenRevocationServiceTrait>>>().cloned();
    if token_revocation_service_data.is_none() {
        error!("TokenRevocationService not found in app_data for jwt_auth_validator_internal");
        return Err((AuthError::new(
            "Internal server configuration error".to_string(),
            500
        ).into(), req));
    }
    let token_revocation_service = token_revocation_service_data.unwrap().into_inner(); 
    
    let token = if let Some(cookie) = req.cookie("access_token") {
        cookie.value().to_string()
    } else if let Some(auth) = credentials {
        auth.token().to_string()
    } else {
        return Err((AuthError::new(
            "No authentication token found".to_string(),
            401
        ).into(), req));
    };

    debug!("Validating JWT token");
    let validation_result = validate_jwt(&token_revocation_service, &token[..], &jwt_secret, Some(TokenType::Access)).await;
    
    match validation_result {
        Ok(claims) => {
            info!("Token validated successfully for user: {}", claims.sub);
            let now = chrono::Utc::now().timestamp();
            let remaining_time = claims.exp - now;
            if remaining_time < 300 { 
                warn!("Token for user {} is about to expire in {} seconds", claims.sub, remaining_time);
            }
            req.extensions_mut().insert(claims);
            Ok(req)
        },
        Err(e) => {
            error!("Token validation failed: {:?}", e);
            Err((AuthError::new(
                "Invalid or expired token".to_string(),
                401
            ).into(), req))
        },
    }
}

pub struct CookieAuth;

impl CookieAuth {
    #[allow(dead_code)]
    pub fn new() -> Self {
        CookieAuth
    }
}

impl<S, B> Transform<S, ServiceRequest> for CookieAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = CookieAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CookieAuthMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct CookieAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for CookieAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        
        let csrf_header = req.headers().get("X-CSRF-Token").cloned();
        let csrf_cookie = req.cookie("csrf_token");
        
        if req.method() != actix_web::http::Method::GET {
            if csrf_header.is_none() || csrf_cookie.is_none() {
                return Box::pin(async move {
                    Err(Error::from(AuthError::new(
                        "CSRF token missing".to_string(),
                        403,
                    )))
                });
            }
            if let (Some(header), Some(cookie)) = (csrf_header, csrf_cookie) {
                if header.to_str().unwrap_or("") != cookie.value() {
                    return Box::pin(async move {
                        Err(Error::from(AuthError::new(
                            "CSRF token mismatch".to_string(),
                            403,
                        )))
                    });
                }
            }
        }
        
        Box::pin(async move {
            let token = match req.cookie("access_token") {
                Some(cookie) => cookie.value().to_string(),
                None => {
                    debug!("No access_token cookie found");
                    return Err(Error::from(AuthError::new(
                        "No access_token cookie found".to_string(),
                        401,
                    )));
                }
            };
            
            let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

            let token_revocation_service_data = req.app_data::<web::Data<Arc<dyn TokenRevocationServiceTrait>>>().cloned();
            
            let token_revocation_service = match token_revocation_service_data {
                Some(service_data) => service_data.into_inner(),
                None => {
                    error!("TokenRevocationService not found in app_data for CookieAuthMiddleware");
                    // This error is now part of the async block, so it will be a Result<_, Error>
                    return Err(Error::from(AuthError::new(
                        "Internal server configuration error".to_string(),
                        500,
                    )));
                }
            };

            match validate_jwt(&token_revocation_service, &token, &jwt_secret, Some(TokenType::Access)).await {
                Ok(claims) => {
                    debug!("Token validated successfully for user: {}", claims.sub);
                    req.extensions_mut().insert(claims);
                    service.call(req).await
                },
                Err(e) => {
                    error!("Token validation failed: {:?}", e);
                    Err(Error::from(AuthError::new(
                        "Invalid or expired token".to_string(),
                        401,
                    )))
                }
            }
        })
    }
}

pub async fn cookie_auth_middleware(
    req: ServiceRequest,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let token_revocation_service_data = req.app_data::<web::Data<Arc<dyn TokenRevocationServiceTrait>>>().cloned();
    if token_revocation_service_data.is_none() {
        error!("TokenRevocationService not found in app_data for cookie_auth_middleware");
        return Err((AuthError::new(
            "Internal server configuration error".to_string(),
            500
        ).into(), req));
    }
    let token_revocation_service = token_revocation_service_data.unwrap().into_inner();
    
    let token = match req.cookie("access_token") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            debug!("No access_token cookie found");
            return Err((
                AuthError::new(
                    "No access token cookie found".to_string(),
                    401
                ).into(),
                req
            ));
        }
    };

    debug!("Validating JWT token from cookie");
    let validation_result = validate_jwt(&token_revocation_service, &token, &jwt_secret, Some(TokenType::Access)).await;
    
    match validation_result {
        Ok(claims) => {
            info!("Cookie token validated successfully for user: {}", claims.sub);
            let now = chrono::Utc::now().timestamp();
            let remaining_time = claims.exp - now;
            if remaining_time < 300 { 
                warn!("Token for user {} is about to expire in {} seconds", claims.sub, remaining_time);
            }
            req.extensions_mut().insert(claims);
            Ok(req)
        },
        Err(e) => {
            error!("Cookie token validation failed: {:?}", e);
            Err((
                AuthError::new(
                    "Invalid or expired token in cookie".to_string(),
                    401
                ).into(),
                req
            ))
        },
    }
}
