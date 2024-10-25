// src/infrastructure/mod.rs

pub mod config;
pub mod database;
pub mod middleware;

// Re-export commonly used items for easier access
pub use config::AppConfig;
pub use database::{create_pool, run_migrations, DatabasePool};
pub use middleware::{
    jwt_auth_validator,         // From `auth.rs` - JWT validation middleware
    AuthError,         // From `auth.rs` - Custom authentication error
    configure_cors,    // From `cors.rs` - CORS configuration middleware
    RequestLogger,     // From `logger.rs` - Request logging middleware
};
