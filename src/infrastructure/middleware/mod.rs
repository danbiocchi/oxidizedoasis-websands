// src/infrastructure/middleware/mod.rs

pub mod auth;
pub mod admin;
pub mod cors;
pub mod logger;
pub mod rate_limit;
pub mod csrf;

pub use admin::admin_validator;

// Re-export commonly used middleware for convenience
pub use auth::{jwt_auth_validator, CookieAuth};
