use crate::core::auth::jwt::{validate_jwt, TokenType};
use actix_web::error::ResponseError;
use actix_web::{dev::ServiceRequest, Error, HttpMessage, HttpResponse, dev::ServiceResponse, dev::Service, dev::Transform, web::Data, cookie::Cookie};
use actix_web_httpauth::extractors::{bearer::BearerAuth, AuthenticationError};
use futures_util::future::{ready, Ready, LocalBoxFuture};
use serde_json::json;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use log::{error, debug, info, warn};


#[derive(Debug)]
pub struct AuthError {
    pub message: String,
}

impl AuthError {
    #[allow(dead_code)]
    pub fn new(message: String, _status_code: u16) -> Self {
        Self { message }
    }
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

// This is the function that HttpAuthentication::bearer will call
pub async fn jwt_auth_validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    // Call our internal function with Some(credentials)
    jwt_auth_validator_internal(req, Some(credentials)).await
}

// This function can be used directly by middleware that needs to handle optional bearer tokens
pub async fn cookie_auth_validator(req: ServiceRequest) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    // Call our internal function with None for credentials
    jwt_auth_validator_internal(req, None).await
}

// Internal implementation that handles both cases
// This is not exported in the public API
async fn jwt_auth_validator_internal(
    req: ServiceRequest, credentials: Option<BearerAuth>) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    
    // First try to get token from cookie
    let token = if let Some(cookie) = req.cookie("access_token") {
        cookie.value().to_string()
    } else if let Some(auth) = credentials {
        // Fallback to Authorization header for backward compatibility
        auth.token().to_string()
    } else {
        return Err((AuthError {
            message: "No authentication token found".to_string()
        }.into(), req));
    };

    debug!("Validating JWT token");

    // Validate as an access token - we don't accept refresh tokens for API access
    let validation_result = validate_jwt(&token[..], &jwt_secret, Some(TokenType::Access)).await;
    
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

// Cookie Auth Middleware Factory
pub struct CookieAuth;

impl CookieAuth {
    #[allow(dead_code)]
    pub fn new() -> Self {
        CookieAuth
    }
}

// Implement the Transform trait for CookieAuth
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

// The middleware service
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
        
        // Check for CSRF token in header for protected routes
        let csrf_header = req.headers().get("X-CSRF-Token").cloned();
        let csrf_cookie = req.cookie("csrf_token");
        
        // Validate CSRF token if this is a non-GET request
        if req.method() != actix_web::http::Method::GET {
            if csrf_header.is_none() || csrf_cookie.is_none() {
                return Box::pin(async move {
                    Err(Error::from(AuthError::new(
                        "CSRF token missing".to_string(),
                        403,
                    )))
                });
            }
            
            // Compare CSRF token from header with cookie
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
            // Extract the JWT token from the cookie
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
            
            // Validate the JWT token
            let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
            match validate_jwt(&token, &jwt_secret, Some(TokenType::Access)).await {
                Ok(claims) => {
                    debug!("Token validated successfully for user: {}", claims.sub);
                    // Add the claims to the request extensions
                    req.extensions_mut().insert(claims);
                    // Call the next service
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

// Cookie-based JWT authentication middleware
pub async fn cookie_auth_middleware(
    req: ServiceRequest,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    
    // Try to get access token from cookie
    let token = match req.cookie("access_token") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            debug!("No access_token cookie found");
            return Err((
                AuthError {
                    message: "No access token cookie found".to_string()
                }.into(),
                req
            ));
        }
    };

    debug!("Validating JWT token from cookie");

    // Validate as an access token
    let validation_result = validate_jwt(&token, &jwt_secret, Some(TokenType::Access)).await;
    
    match validation_result {
        Ok(claims) => {
            info!("Cookie token validated successfully for user: {}", claims.sub);
            
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
            error!("Cookie token validation failed: {:?}", e);
            Err((
                AuthError {
                    message: "Invalid or expired token in cookie".to_string()
                }.into(),
                req
            ))
        },
    }
}
