use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::Connection;
use log::{info, debug, error, warn};
use dotenv::dotenv;
use actix_files as fs;
use actix_cors::Cors;
use actix_web_httpauth::middleware::HttpAuthentication;
use env_logger::Env;
use actix_governor::{Governor, GovernorConfigBuilder};
use std::env;
use std::time::Duration;
use sqlx::migrate::MigrateDatabase;
use crate::middleware::validator;
use crate::handlers::admin::admin_validator;
use crate::middleware::cors_logger;
use crate::email::{EmailServiceTrait, RealEmailService};
mod config;
use config::Config;
use std::sync::Arc;
use actix_web::{App, http, HttpResponse, HttpServer, web};

mod handlers;
mod models;
mod auth;
mod email;
mod middleware;
mod validation;

/// Sets up the database connection pool and runs migrations if specified.
///
/// This function performs the following steps:
/// 1. Retrieves database configuration from environment variables.
/// 2. Validates the database URL format.
/// 3. Creates the database if it doesn't exist.
/// 4. Grants necessary privileges to the application user.
/// 5. Sets up a connection pool for the application.
/// 6. Runs database migrations if specified.
///
/// # Arguments
/// * `run_migrations` - A boolean indicating whether to run migrations.
///
/// # Returns
/// * `Result<sqlx::Pool<Postgres>, Box<dyn std::error::Error>>` - A database connection pool on success, or an error.
async fn setup_database(run_migrations: bool) -> Result<sqlx::Pool<Postgres>, Box<dyn std::error::Error>> {
    // Fetch environment variables
    let su_database_url = env::var("SU_DATABASE_URL")
        .map_err(|_| "SU_DATABASE_URL is not set in the environment variables")?;
    let database_url = env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is not set in the environment variables")?;
    let db_name = env::var("DB_NAME")
        .map_err(|_| "DB_NAME is not set in the environment variables")?;
    let db_user = env::var("DB_USER")
        .map_err(|_| "DB_USER is not set in the environment variables")?;

    debug!("Super user database URL: {}", su_database_url);
    debug!("Application database URL: {}", database_url);
    debug!("Database name: {}", db_name);
    debug!("Database user: {}", db_user);

    // Validate URL format
    if !su_database_url.starts_with("postgres://") || !database_url.starts_with("postgres://") {
        return Err("Invalid database URL format. Must start with 'postgres://'".into());
    }

    info!("Checking if database '{}' exists", db_name);

    // Check if database exists, create if it doesn't
    if !Postgres::database_exists(&su_database_url).await? {
        info!("Database '{}' does not exist. Attempting to create...", db_name);
        match Postgres::create_database(&su_database_url).await {
            Ok(_) => info!("Database '{}' created successfully", db_name),
            Err(e) => {
                error!("Failed to create database '{}': {:?}", db_name, e);
                return Err(Box::new(e));
            }
        }
    } else {
        info!("Database '{}' already exists", db_name);
    }

    // Connect as super user to grant privileges
    info!("Connecting to database as super user");
    let mut su_conn = match sqlx::PgConnection::connect(&su_database_url).await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Failed to connect as super user: {:?}", e);
            return Err(Box::new(e));
        }
    };

    info!("Granting privileges to application user '{}'", db_user);

    // Grant privileges to application user
    let grant_query = format!("GRANT ALL PRIVILEGES ON DATABASE \"{}\" TO \"{}\"", db_name, db_user);
    match sqlx::query(&grant_query).execute(&mut su_conn).await {
        Ok(_) => info!("Privileges granted successfully to '{}'", db_user),
        Err(e) => {
            error!("Failed to grant privileges to '{}': {:?}", db_user, e);
            return Err(Box::new(e));
        }
    }

    // Close super user connection
    drop(su_conn);
    info!("Closed super user connection");

    // Set up connection pool with application usr
    info!("Setting up connection pool for application user");
    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .max_lifetime(Some(Duration::from_secs(30 * 60))) // 30 minutes
        .idle_timeout(Some(Duration::from_secs(10 * 60))) // 10 minutes
        .acquire_timeout(Duration::from_secs(30))
        .connect(&database_url)
        .await {
        Ok(pool) => {
            info!("Connection pool established successfully");
            pool
        },
        Err(e) => {
            error!("Failed to establish connection pool: {:?}", e);
            return Err(Box::new(e));
        }
    };

    // Run migrations if specified
    if run_migrations {
        info!("Running database migrations");
        match sqlx::migrate!("./migrations").run(&pool).await {
            Ok(_) => info!("Migrations completed successfully"),
            Err(e) => {
                error!("Migration failed: {:?}", e);
                return Err(Box::new(e));
            }
        }
    } else {
        warn!("Skipping database migrations. Ensure your database schema is up to date.");
    }

    // Test the connection
    info!("Testing database connection");
    match pool.acquire().await {
        Ok(_) => info!("Database connection test successful"),
        Err(e) => {
            error!("Failed to acquire a database connection: {:?}", e);
            return Err(Box::new(e));
        }
    }

    Ok(pool)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from .env file
    dotenv().ok();

    // Initialize the logger with the default filter level set to "debug"
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    info!("Starting OxidizedOasis-WebSands application");

    // Ensure critical environment variables are set
    let _su_database_url = env::var("SU_DATABASE_URL")
        .expect("SU_DATABASE_URL must be set in environment variables");
    let _app_database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in environment variables");

    // Determine whether to run database migrations
    let run_migrations = env::var("RUN_MIGRATIONS")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true);

    // Set up the database connection pool
    let pool = match setup_database(run_migrations).await {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to set up database: {:?}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    };

    // Initialize application configuration
    let config = Config::new();

    // Determine the server host and port from environment variables or use defaults
    let host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_string());
    let server_addr = format!("{}:{}", host, port);

    debug!("Server will be listening on: {}", server_addr);

    // Configure rate limiting
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(2)
        .burst_size(5)
        .finish()
        .unwrap();

    // Determine the allowed origin for CORS based on the environment
    let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
    let allowed_origin = match environment.as_str() {
        "production" => env::var("PRODUCTION_URL").expect("PRODUCTION_URL must be set in production"),
        "development" => env::var("DEVELOPMENT_URL").expect("DEVELOPMENT_URL must be set for development"),
        _ => panic!("ENVIRONMENT must be set to either 'production' or 'development'"),
    };

    // Initialize the email service
    let email_service: Arc<dyn EmailServiceTrait> = Arc::new(RealEmailService::new());

    // Configure and start the HTTP server
    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allowed_origin(&allowed_origin)
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT, http::header::CONTENT_TYPE])
            .max_age(3600);

        // Build the application with all middleware and service configurations
        App::new()
            .wrap(cors)  // Apply CORS middleware
            .app_data(web::Data::new(pool.clone()))  // Share database pool across handlers
            .app_data(web::Data::new(email_service.clone()))  // Use Arc<dyn EmailServiceTrait>
            .wrap(cors_logger::CorsLogger::new(config.clone()))  // Custom CORS logging
            .wrap(actix_web::middleware::Logger::default())  // Standard request logging
            .wrap(  // Apply security headers
                    actix_web::middleware::DefaultHeaders::new()
                        .add(("X-XSS-Protection", "1; mode=block"))
                        .add(("X-Frame-Options", "DENY"))
                        .add(("X-Content-Type-Options", "nosniff"))
                        .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
            )
            // Public pages with rate limiting
            .service(
                web::scope("/users")
                    .wrap(Governor::new(&governor_conf))
                    .route("/register", web::post().to(handlers::user::create_user))
                    .route("/login", web::post().to(handlers::user::login_user))
                    .route("/verify", web::get().to(handlers::user::verify_email))
            )
            // Protected API pages
            .service(
                web::scope("/api")
                    .wrap(HttpAuthentication::bearer(validator))
                    .service(handlers::user::get_current_user)
                    .service(handlers::user::get_user)
                    .service(handlers::user::update_user)
                    .service(handlers::user::delete_user)
            )
            // Admin pages with separate authentication
            .service(
                web::scope("/admin")
                    .wrap(HttpAuthentication::bearer(admin_validator))
                    .route("/dashboard", web::get().to(handlers::admin::admin_dashboard))
            )
            // Serve static files
            .service(fs::Files::new("/", "./frontend/dist").index_file("index.html"))
            // Default service for unhandled pages
            .default_service(web::route().to(|| async {
                HttpResponse::Ok().content_type("text/html").body(
                    std::fs::read_to_string("./frontend/dist/index.html").unwrap()
                )
            }))
    })
        .bind(server_addr)?  // Bind the server to the specified address
        .run()  // Run the server
        .await  // Wait for the server to complete
}