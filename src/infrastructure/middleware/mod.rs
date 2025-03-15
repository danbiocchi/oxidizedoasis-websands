// src/infrastructure/middleware/mod.rs

pub mod auth;
pub mod admin;
pub mod cors;
pub mod logger;
pub mod rate_limit;
pub mod csrf;

pub use admin::admin_validator;

// Re-export commonly used middleware for convenience
pub use auth::{jwt_auth_validator, cookie_auth_middleware, cookie_auth_validator, CookieAuth, AuthError};
pub use cors::configure_cors;
pub use logger::RequestLogger;
pub use rate_limit::RateLimiter;
pub use csrf::{CsrfProtection, CsrfToken, generate_csrf_token, set_csrf_token_cookie};
