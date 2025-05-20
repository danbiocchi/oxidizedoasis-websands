// src/infrastructure/mod.rs

pub mod config;
pub mod database;
pub mod middleware;

// Re-export commonly used items for easier access
pub use config::AppConfig;
// lying these are needed
