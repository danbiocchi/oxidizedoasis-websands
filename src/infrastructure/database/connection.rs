use sqlx::postgres::{PgPool, PgPoolOptions, Postgres};
use sqlx::{Executor, Error as SqlxError};
use sqlx::migrate::{MigrateDatabase, MigrateError};
use std::time::Duration;
use log::{info, debug, error, warn};
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

async fn verify_permissions(pool: &PgPool) -> Result<bool, DatabaseError> {
    debug!("Verifying database permissions...");
    
    // Try to create a test table to verify permissions
    let result = pool.execute(
        "CREATE TABLE IF NOT EXISTS _permission_test (id int)"
    ).await;
    
    // Clean up the test table regardless of the result
    let _ = pool.execute(
        "DROP TABLE IF EXISTS _permission_test"
    ).await;
    
    match result {
        Ok(_) => {
            debug!("Permission verification successful");
            Ok(true)
        }
        Err(e) => {
            warn!("Permission verification failed: {}", e);
            Ok(false)
        }
    }
}

async fn reset_database(base_url: &str, db_name: &str) -> Result<(), DatabaseError> {
    info!("Attempting to reset database '{}'...", db_name);
    
    // Connect to postgres database for administrative operations
    let temp_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(base_url)
        .await
        .map_err(DatabaseError::Connection)?;

    // Drop existing database if it exists
    let drop_query = format!(
        "DROP DATABASE IF EXISTS {} WITH (FORCE)",
        db_name
    );
    
    match temp_pool.execute(&*drop_query).await {
        Ok(_) => info!("Successfully dropped existing database"),
        Err(e) => {
            error!("Failed to drop database: {}", e);
            return Err(DatabaseError::Setup(e));
        }
    }

    // Create fresh database
    Postgres::create_database(&format!("{}/{}", base_url, db_name)).await
        .map_err(|e| DatabaseError::Connection(e))?;
    
    info!("Database reset successful");
    Ok(())
}

async fn setup_database(pool: &PgPool, db_name: &str, app_user: &str, environment: &str) -> Result<(), DatabaseError> {
    debug!("Setting up database schema and permissions...");
    
    // Create base queries that are common to both environments
    let mut setup_queries = vec![
        // Ensure schema exists and is owned by superuser
        "CREATE SCHEMA IF NOT EXISTS public".to_string(),
    ];

    if environment == "development" {
        // Development mode: grant permissions to postgres and app_user
        setup_queries.extend(vec![
            // Ensure postgres user has full access for CLI operations
            format!("GRANT ALL PRIVILEGES ON DATABASE {} TO postgres", db_name),
            "GRANT ALL PRIVILEGES ON SCHEMA public TO postgres".to_string(),
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO postgres".to_string(),
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO postgres".to_string(),
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON FUNCTIONS TO postgres".to_string(),
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TYPES TO postgres".to_string(),
            
            // Grant permissions to app_user
            format!("GRANT CONNECT ON DATABASE {} TO {}", db_name, app_user),
            format!("GRANT USAGE, CREATE ON SCHEMA public TO {}", app_user),
            format!("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}", app_user),
            format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}", app_user),
            format!("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {}", app_user),
            format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}", app_user),
        ]);
    } else {
        // Production mode: restrict access to only the app_user
        setup_queries.extend(vec![
            // Revoke public access
            format!("REVOKE ALL ON DATABASE {} FROM PUBLIC", db_name),
            "REVOKE ALL ON SCHEMA public FROM PUBLIC".to_string(),
            
            // Grant minimal required permissions to app_user
            format!("GRANT CONNECT ON DATABASE {} TO {}", db_name, app_user),
            format!("GRANT USAGE, CREATE ON SCHEMA public TO {}", app_user),
            format!("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}", app_user),
            format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}", app_user),
            format!("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {}", app_user),
            format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}", app_user),
        ]);
    }

    for query in setup_queries {
        match pool.execute(&*query).await {
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

async fn setup_and_migrate(su_pool: &PgPool, db_name: &str, app_user: &str, environment: &str) -> Result<(), DatabaseError> {
    // Set up database permissions
    setup_database(su_pool, db_name, app_user, environment).await?;
    
    // Run migrations
    info!("Running migrations...");
    sqlx::migrate!("./migrations")
        .run(su_pool)
        .await
        .map_err(DatabaseError::Migration)?;
    
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
    let environment = std::env::var("ENVIRONMENT")
        .unwrap_or_else(|_| "production".to_string());

    debug!("Initializing database connection...");

    // Validate URL format
    if !su_database_url.starts_with("postgres://") || !database_url.starts_with("postgres://") {
        return Err(DatabaseError::Configuration("Invalid database URL format".into()));
    }

    // Extract base URL for potential database reset
    let base_url = su_database_url.replace(&format!("/{}", db_name), "/postgres");

    // First check if database exists
    let db_exists = Postgres::database_exists(&su_database_url).await
        .map_err(DatabaseError::Connection)?;

    if environment == "development" {
        if db_exists {
            // Connect to existing database
            let su_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&su_database_url)
                .await
                .map_err(DatabaseError::Connection)?;
            
            // Verify permissions on existing database
            if !verify_permissions(&su_pool).await? {
                warn!("Permission issues detected in development mode, attempting database reset...");
                // Drop superuser connection before reset
                drop(su_pool);
                
                // Reset the database
                reset_database(&base_url, &db_name).await?;
                
                // Reconnect as superuser to the new database
                let su_pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&su_database_url)
                    .await
                    .map_err(DatabaseError::Connection)?;
                
                // Set up fresh permissions and run migrations
                setup_and_migrate(&su_pool, &db_name, &db_user, &environment).await?;
            }
        } else {
            // Create new database
            info!("Creating new database '{}'...", db_name);
            Postgres::create_database(&su_database_url).await
                .map_err(|e| DatabaseError::Connection(e))?;
            
            // Connect to new database
            let su_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&su_database_url)
                .await
                .map_err(DatabaseError::Connection)?;
            
            // Set up permissions and run migrations
            setup_and_migrate(&su_pool, &db_name, &db_user, &environment).await?;
        }
    } else {
        // Production mode: simpler flow
        if !db_exists {
            info!("Creating database '{}'...", db_name);
            Postgres::create_database(&su_database_url).await
                .map_err(|e| DatabaseError::Connection(e))?;
        }
        
        let su_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&su_database_url)
            .await
            .map_err(DatabaseError::Connection)?;
        
        // Set up permissions and run migrations
        setup_and_migrate(&su_pool, &db_name, &db_user, &environment).await?;
    }

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
