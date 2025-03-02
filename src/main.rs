use std::env;
use std::sync::Arc;
use std::time::Duration;
use actix_files as fs;
use actix_web::{App, HttpResponse, HttpServer, web, middleware};
use dotenv::dotenv;
use env_logger::Env;
use log::{debug, error, info, warn};
use sqlx::postgres::Postgres;
use serde_json::json;

// Environment validation function
fn validate_critical_env_vars() -> Result<(), Box<dyn std::error::Error>> {
    let required_vars = [
        "DATABASE_URL",
        "JWT_SECRET",
        "SMTP_SERVER",
        "ADMIN_EMAIL",
    ];
    
    for var in required_vars {
        if env::var(var).is_err() {
            return Err(format!("Missing required environment variable: {}", var).into());
        }
    }
    Ok(())
}

// Only import what we actually use
use crate::api::routes::configure_routes;
use crate::api::handlers::user_handler::create_handler as create_user_handler;
use crate::core::email::EmailService;
use crate::core::user::{User, UserRepository};
use crate::core::auth::token_revocation::TokenRevocationService;
use crate::core::auth::active_token::ActiveTokenService;
use crate::infrastructure::{AppConfig, configure_cors, create_pool, RequestLogger, RateLimiter};

mod api;
mod common;
mod core;
mod infrastructure;

/// Sets up the database connection with migrations
/// Includes timeout protection to prevent hanging during startup
async fn setup_database(config: &AppConfig, run_migrations: bool) -> Result<sqlx::Pool<Postgres>, Box<dyn std::error::Error>> {
    let pool = create_pool(config).await?;

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

    Ok(pool)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize environment and enhanced logging
    // Timestamps in logs are crucial for security auditing
    dotenv().ok();
    env_logger::Builder::from_env(Env::default().default_filter_or("debug"))
        .format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "{} [{}] - {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();

    info!("Starting OxidizedOasis-WebSands application");

    // Validate critical environment variables
    if let Err(e) = validate_critical_env_vars() {
        error!("Environment validation failed: {}", e);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
    }

    // Load configuration with proper error handling
    let config = match AppConfig::from_env() {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {:?}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    };

    // Clone the config for use in the HttpServer closure
    let config_clone = config.clone();
    
    // Store configuration values we need after the move into HttpServer::new
    let server_host = config.server.host.clone();
    let server_port = config.server.port.clone();

    // Database migration configuration
    let run_migrations = env::var("RUN_MIGRATIONS")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true);

    // Setup database with timeout protection
    // This prevents the application from hanging during startup
    let pool = match tokio::time::timeout(
        Duration::from_secs(30),
        setup_database(&config, run_migrations)
    ).await {
        Ok(Ok(pool)) => pool,
        Ok(Err(e)) => {
            error!("Database setup failed: {:?}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
        Err(_) => {
            error!("Database setup timed out");
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Database setup timed out"));
        }
    };

    // Initialize services
    let email_service = Arc::new(EmailService::new());
    
    // Initialize active token service first
    let active_token_service = Arc::new(ActiveTokenService::new(pool.clone()));
    crate::core::auth::jwt::init_active_token_service(active_token_service.clone());
    
    // Initialize token revocation service with active token service
    // Create a mutable instance first, set the active token service, then wrap in Arc
    let mut token_revocation_service_mut = TokenRevocationService::new(pool.clone());
    token_revocation_service_mut.set_active_token_service(active_token_service.clone());
    let token_revocation_service = Arc::new(token_revocation_service_mut);
    crate::core::auth::jwt::init_token_revocation(token_revocation_service.clone());
    
    // Start a background task to clean up expired revoked tokens
    let cleanup_service = token_revocation_service.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Run every hour
        loop {
            interval.tick().await;
            match cleanup_service.cleanup_expired_tokens().await {
                Ok(count) => {
                    if count > 0 {
                        info!("Cleaned up {} expired revoked tokens", count);
                    }
                },
                Err(e) => {
                    error!("Failed to clean up expired revoked tokens: {:?}", e);
                }
            }
        }
    });

    // Start a background task to clean up expired active tokens
    let cleanup_active_service = active_token_service.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Run every hour
        loop {
            interval.tick().await;
            match cleanup_active_service.cleanup_expired_tokens().await {
                Ok(count) => {
                    if count > 0 {
                        info!("Cleaned up {} expired active tokens", count);
                    }
                },
                Err(e) => {
                    error!("Failed to clean up expired active tokens: {:?}", e);
                }
            }
        }
    });
    
    // Create user handler
    let user_handler = web::Data::new(create_user_handler(
        pool.clone(),
        email_service.clone(),
    ));

    // Server configuration
    let server_addr = format!("{}:{}", server_host, server_port);
    debug!("Server will be listening on: {}", server_addr);

    // Start HTTP server with security configurations
    HttpServer::new(move || {
        let config = config_clone.clone();
        debug!("Setting up new application instance");
        App::new()
            // Security middleware stack - order matters!
            // 1. Rate limiting first to prevent DoS
            .wrap(RateLimiter::new())
            // 2. CORS protection
            .wrap(configure_cors())
            // 3. Security headers
            .wrap(
                middleware::DefaultHeaders::new()
                    // Prevent XSS attacks
                    .add(("X-XSS-Protection", "1; mode=block"))
                    // Prevent clickjacking
                    .add(("X-Frame-Options", "DENY"))
                    // Prevent MIME type sniffing
                    .add(("X-Content-Type-Options", "nosniff"))
                    // Control referrer information
                    .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
                    // Restrict browser features
                    .add(("Permissions-Policy",
                          "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"))
                    // Cross-Origin protections
                    .add(("Cross-Origin-Embedder-Policy", "require-corp"))
                    .add(("Cross-Origin-Opener-Policy", "same-origin"))
                    .add(("Cross-Origin-Resource-Policy", "same-origin"))
                    // Content Security Policy
                    .add((
                        "Content-Security-Policy",
                        "default-src 'self'; \
                         script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; \
                         style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; \
                         img-src 'self' data:; \
                         connect-src 'self' ws://127.0.0.1:* wss://127.0.0.1:*; \
                         font-src 'self' https://cdnjs.cloudflare.com; \
                         object-src 'none'; \
                         base-uri 'self'; \
                         form-action 'self'; \
                         frame-ancestors 'none'; \
                         worker-src 'self' blob:; \
                         upgrade-insecure-requests;"
                    ))
            )
            // 4. Enhanced request logging for security auditing (with referer and user agent)
            .wrap(RequestLogger::new())
            // 5. Compression last (after security controls)
            .wrap(middleware::Compress::default())

            // App Data
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(email_service.clone()))
            .app_data(user_handler.clone())
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(UserRepository::new(pool.clone())))

            // JSON payload protection
            .app_data(web::JsonConfig::default()
                .limit(4096)  // 4kb limit to prevent DOS
                .error_handler(|err, _| {
                    actix_web::error::InternalError::from_response(
                        err,
                        HttpResponse::BadRequest()
                            .content_type("application/json")
                            .body(r#"{"error":"Invalid JSON payload"}"#),
                    )
                        .into()
                }))

            // Serve static files with proper MIME types
            .service(
                fs::Files::new("/static/css", "./frontend/static/css")
                    .prefer_utf8(true)
                    .use_last_modified(true)
            )
            
            // API Routes configuration - after static CSS but before catch-all
            .configure(configure_routes)
            
            // Catch-all static file serving
            .service(
                fs::Files::new("/", "./frontend/dist")
                    .index_file("index.html")
                    .prefer_utf8(true)
                    .use_last_modified(true)
            )
            // Handle all other routes by serving index.html for client-side routing
            .default_service(web::route().to(|| async {
                match std::fs::read_to_string("./frontend/dist/index.html") {
                    Ok(contents) => HttpResponse::Ok()
                        .content_type("text/html; charset=utf-8")
                        .append_header(("Cache-Control", "no-store, must-revalidate"))
                        .append_header(("Pragma", "no-cache"))
                        .append_header(("Expires", "0"))
                        .body(contents),
                    Err(e) => {
                        error!("Failed to read index.html: {}", e); // Keep detailed logging
                        HttpResponse::InternalServerError()
                            .content_type("application/json")
                            .body(r#"{"error": "An unexpected error occurred"}"#) // Generic public message
                    }
                }
            }))
    })
        // Server configuration for security and performance
        .keep_alive(Duration::from_secs(75))           // Prevent connection spam
        .client_request_timeout(Duration::from_secs(60))       // Prevent hanging connections
        .server_hostname(server_host)                  // Explicit hostname
        .backlog(1024)                                // Connection queue size
        .workers(num_cpus::get() * 2)                 // Optimal worker threads
        .shutdown_timeout(30)                         // Graceful shutdown
        .bind(&server_addr)?
        .run()
        .await
}
