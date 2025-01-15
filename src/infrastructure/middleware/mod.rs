// src/infrastructure/middleware/mod.rs

pub mod auth;
pub mod cors;
pub mod logger;
pub mod rate_limit;

// Re-export commonly used middleware for convenience
pub use auth::{jwt_auth_validator, AuthError};
pub use cors::configure_cors;
pub use logger::RequestLogger;
pub use rate_limit::RateLimiter;
