use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorForbidden,
    FromRequest,
    http::{header, Method},
    web, Error, HttpMessage, HttpRequest,
};
use futures_util::future::{ok, ready, LocalBoxFuture, Ready};
use log::{debug, error, warn};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::{
 
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

// CSRF token structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CsrfToken {
    pub token: String,
}

impl CsrfToken {
    pub fn new() -> Self {
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        Self { token }
    }
}

// CSRF protection middleware
pub struct CsrfProtection;

impl<S, B> Transform<S, ServiceRequest> for CsrfProtection
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = CsrfProtectionMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CsrfProtectionMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct CsrfProtectionMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for CsrfProtectionMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        // Skip CSRF check for safe methods (GET, HEAD, OPTIONS)
        if req.method() == Method::GET || req.method() == Method::HEAD || req.method() == Method::OPTIONS {
            return Box::pin(async move { service.call(req).await });
        }

        // Skip CSRF check for API endpoints that don't need it
        let path = req.path();
        if path.starts_with("/api/") && !path.contains("/users/") {
            return Box::pin(async move { service.call(req).await });
        }

        // Get CSRF token from header
        let header_token = req
            .headers()
            .get("X-CSRF-Token")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        // Get CSRF token from cookie
        let cookie_token = req
            .cookie("csrf_token")
            .map(|c| c.value().to_string());

        // Validate tokens
        let valid = match (header_token, cookie_token) {
            (Some(header), Some(cookie)) => {
                let valid = header == cookie;
                if !valid {
                    warn!("CSRF token mismatch: header={}, cookie={}", header, cookie);
                }
                valid
            },
            _ => {
                warn!("Missing CSRF token: header={:?}, cookie={:?}", 
                      req.headers().get("X-CSRF-Token"), 
                      req.cookie("csrf_token"));
                false
            }
        };

        if valid {
            Box::pin(async move { service.call(req).await })
        } else {
            Box::pin(async move {
                Err(ErrorForbidden("Invalid CSRF token"))
            })
        }
    }
}

// Helper function to generate a new CSRF token
pub fn generate_csrf_token() -> CsrfToken {
    CsrfToken::new()
}

// Helper function to set CSRF token cookie
pub fn set_csrf_token_cookie(req: &HttpRequest) -> CsrfToken {
    // Check if there's already a CSRF token in the cookie
    if let Some(cookie) = req.cookie("csrf_token") {
        return CsrfToken { token: cookie.value().to_string() };
    }
    
    // Generate a new token
    let token = generate_csrf_token();
    
    // Store in request extensions for handlers to access
    req.extensions_mut().insert(token.clone());
    
    token
}

// Extractor for CSRF token from request
pub struct CsrfTokenExtractor(pub String);

impl FromRequest for CsrfTokenExtractor {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        // Try to get token from extensions (set by middleware)
        if let Some(token) = req.extensions().get::<CsrfToken>() {
            return ok(CsrfTokenExtractor(token.token.clone()));
        }
        
        // Try to get from cookie
        if let Some(cookie) = req.cookie("csrf_token") {
            return ok(CsrfTokenExtractor(cookie.value().to_string()));
        }
        
        // Generate new token
        let token = generate_csrf_token();
        ok(CsrfTokenExtractor(token.token))
    }
}