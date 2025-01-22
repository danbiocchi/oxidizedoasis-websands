use sqlx::postgres::{PgPool, PgPoolOptions, Postgres};
use sqlx::{Executor, Error as SqlxError};
use sqlx::migrate::{MigrateDatabase, MigrateError};
use std::time::Duration;
use log::{info, debug, error};
use crate::infrastructure::AppConfig;

pub type DatabasePool = PgPool;

#[derive(Debug)]
pub enum DatabaseError {
    Configuration(String),
    Connection(SqlxError),
    Setup(SqlxError),
    Migration(MigrateError),
    Permission(SqlxError),
}

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(msg) => write!(f, "Database configuration error: {}", msg),
            Self::Connection(e) => write!(f, "Database connection error: {}", e),
            Self::Setup(e) => write!(f, "Database setup error: {}", e),
            Self::Migration(e) => write!(f, "Database migration error: {}", e),
            Self::Permission(e) => write!(f, "Database permission error: {}", e),
        }
    }
}

impl std::error::Error for DatabaseError {}

async fn setup_database(pool: &PgPool, db_name: &str, app_user: &str) -> Result<(), DatabaseError> {
    debug!("Setting up database schema and permissions...");
    
    // Create schema and set up permissions
    let setup_queries = [
        // Ensure schema exists and is owned by superuser
        "CREATE SCHEMA IF NOT EXISTS public",
        
        // Grant connect permission
        &format!("GRANT CONNECT ON DATABASE {} TO {}", db_name, app_user),
        
        // Grant schema usage and create permissions
        &format!("GRANT USAGE, CREATE ON SCHEMA public TO {}", app_user),
        
        // Grant table permissions (including future tables)
        &format!("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}", app_user),
        &format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}", app_user),
        
        // Grant sequence permissions (including future sequences)
        &format!("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {}", app_user),
        &format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}", app_user),
        
        // Note: CREATE permission on schema level (granted above) allows creating indexes
    ];

    for query in setup_queries {
        match pool.execute(query).await {
            Ok(_) => debug!("Successfully executed: {}", query),
            Err(e) => {
                error!("Failed to execute setup query '{}': {}", query, e);
                return Err(DatabaseError::Setup(e));
            }
        }
    }

    info!("Database schema and permissions set up successfully");
    Ok(())
}

pub async fn create_pool(_x: &AppConfig) -> Result<DatabasePool, DatabaseError> {
    // Get configuration from environment
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| DatabaseError::Configuration("DATABASE_URL is not set".into()))?;
    let su_database_url = std::env::var("SU_DATABASE_URL")
        .map_err(|_| DatabaseError::Configuration("SU_DATABASE_URL is not set".into()))?;
    let db_name = std::env::var("DB_NAME")
        .map_err(|_| DatabaseError::Configuration("DB_NAME is not set".into()))?;
    let db_user = std::env::var("DB_USER")
        .map_err(|_| DatabaseError::Configuration("DB_USER is not set".into()))?;

    debug!("Initializing database connection...");

    // Validate URL format
    if !su_database_url.starts_with("postgres://") || !database_url.starts_with("postgres://") {
        return Err(DatabaseError::Configuration("Invalid database URL format".into()));
    }

    // First connect as superuser for setup
    let su_pool = PgPoolOptions::new()
        .max_connections(1) // Only need one connection for setup
        .connect(&su_database_url)
        .await
        .map_err(DatabaseError::Connection)?;

    // Create database if it doesn't exist
    let base_url = su_database_url.replace(&format!("/{}", db_name), "/postgres");
    if !Postgres::database_exists(&su_database_url).await
        .map_err(|e| DatabaseError::Connection(e))? {
        info!("Creating database '{}'...", db_name);
        // Connect to default postgres database to create new database
        Postgres::create_database(&base_url).await
            .map_err(|e| DatabaseError::Connection(e))?;
    }

    // Set up schema and permissions
    setup_database(&su_pool, &db_name, &db_user).await?;

    // Run migrations as superuser
    info!("Running database migrations...");
    sqlx::migrate!("./migrations")
        .run(&su_pool)
        .await
        .map_err(DatabaseError::Migration)?;

    // Drop superuser connection
    drop(su_pool);

    // Create application user pool for normal operations
    info!("Creating application user connection pool...");
    let app_pool = PgPoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .max_lifetime(Some(Duration::from_secs(30 * 60)))
        .idle_timeout(Some(Duration::from_secs(10 * 60)))
        .acquire_timeout(Duration::from_secs(30))
        .connect(&database_url)
        .await
        .map_err(DatabaseError::Connection)?;

    info!("Database connection pool established successfully");
    Ok(app_pool)
}
