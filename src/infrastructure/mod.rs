// src/infrastructure/mod.rs

pub mod config;
pub mod database;
pub mod middleware;

// Re-export commonly used items for easier access
pub use config::AppConfig;
// lying these are needed
pub use database::{create_pool, DatabasePool};
pub use middleware::cors::configure_cors;
pub use middleware::logger::RequestLogger;
pub use middleware::rate_limit::RateLimiter;
