// src/infrastructure/mod.rs
pub mod config;
pub mod database;
pub mod middleware;

// Re-export commonly used items
pub use config::AppConfig;
pub use database::create_pool;
pub use middleware::{
    auth_validator,
    configure_cors,
    RequestLogger,
    rate_limit::configure_rate_limit,
};