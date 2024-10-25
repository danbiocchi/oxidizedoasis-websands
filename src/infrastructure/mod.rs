// src/infrastructure/mod.rs
pub mod config;
pub mod database;
pub mod middleware;

// Re-export commonly used items
pub use config::AppConfig;
