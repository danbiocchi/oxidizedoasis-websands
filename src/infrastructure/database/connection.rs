use sqlx::postgres::{PgPool, PgPoolOptions, Postgres};
use sqlx::Connection;
use std::time::Duration;
use log::{info, debug, error};
use sqlx::migrate::MigrateDatabase;
use crate::infrastructure::AppConfig;

pub type DatabasePool = PgPool;

pub async fn create_pool(x: &AppConfig) -> Result<DatabasePool, Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is not set in the environment variables")?;
    let su_database_url = std::env::var("SU_DATABASE_URL")
        .map_err(|_| "SU_DATABASE_URL is not set in the environment variables")?;
    let db_name = std::env::var("DB_NAME")
        .map_err(|_| "DB_NAME is not set in the environment variables")?;
    let db_user = std::env::var("DB_USER")
        .map_err(|_| "DB_USER is not set in the environment variables")?;

    debug!("Setting up database connection...");

    // Validate URL format
    if !su_database_url.starts_with("postgres://") || !database_url.starts_with("postgres://") {
        return Err("Invalid database URL format. Must start with 'postgres://'".into());
    }

    // Create database if it doesn't exist
    if !Postgres::database_exists(&su_database_url).await? {
        info!("Creating database '{}'...", db_name);
        Postgres::create_database(&su_database_url).await?;
    }

    // Set up connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .max_lifetime(Some(Duration::from_secs(30 * 60)))
        .idle_timeout(Some(Duration::from_secs(10 * 60)))
        .acquire_timeout(Duration::from_secs(30))
        .connect(&database_url)
        .await?;

    info!("Database connection pool established successfully");
    Ok(pool)
}