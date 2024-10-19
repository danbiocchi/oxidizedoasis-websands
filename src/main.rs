use std::env;
use std::sync::Arc;
use std::time::Duration;

use actix_files as fs;
use actix_web::{App, HttpResponse, HttpServer, web};
use actix_web_httpauth::middleware::HttpAuthentication;
use dotenv::dotenv;
use env_logger::Env;
use log::{debug, error, info, warn};
use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::migrate::MigrateDatabase;

use crate::api::handlers::user_handler::create_handler as create_user_handler;
use crate::api::routes::configure_routes;
use crate::core::email::EmailService;
use crate::infrastructure::config::AppConfig;
use crate::infrastructure::database::create_pool;
use crate::infrastructure::middleware::{
    auth_validator,
    configure_cors,
    RequestLogger,
    rate_limit::configure_rate_limit,
};

mod api;
mod common;
mod core;
mod infrastructure;

async fn setup_database(run_migrations: bool) -> Result<sqlx::Pool<Postgres>, Box<dyn std::error::Error>> {
    let config = AppConfig::from_env()?;
    let pool = create_pool(&config).await?;

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
    // Initialize environment
    dotenv().ok();
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();
    info!("Starting OxidizedOasis-WebSands application");

    // Load configuration
    let config = match AppConfig::from_env() {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {:?}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    };

    // Setup database
    let run_migrations = env::var("RUN_MIGRATIONS")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true);

    let pool = match setup_database(run_migrations).await {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to set up database: {:?}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    };

    // Initialize services
    let email_service = Arc::new(EmailService::new());

    // Create user handler
    let user_handler = web::Data::new(create_user_handler(
        pool.clone(),
        email_service.clone(),
    ));

    // Server configuration
    let server_addr = format!("{}:{}", config.server.host, config.server.port);
    debug!("Server will be listening on: {}", server_addr);

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            // Middleware
            .wrap(configure_cors())
            .wrap(RequestLogger::new())
            .wrap(actix_web::middleware::Logger::default())
            .wrap(
                actix_web::middleware::DefaultHeaders::new()
                    .add(("X-XSS-Protection", "1; mode=block"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
            )
            // App Data
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(email_service.clone()))
            .app_data(user_handler.clone())
            .app_data(web::Data::new(config.clone()))

            // Public routes with rate limiting
            .service(
                web::scope("/users")
                    .wrap(configure_rate_limit())
                    .configure(configure_routes::public_routes)
            )

            // Protected API routes
            .service(
                web::scope("/api")
                    .wrap(HttpAuthentication::bearer(auth_validator))
                    .configure(configure_routes::protected_routes)
            )

            // Admin routes
            .service(
                web::scope("/admin")
                    .wrap(HttpAuthentication::bearer(auth_validator))
                    .configure(configure_routes::admin_routes)
            )

            // Static files and frontend
            .service(fs::Files::new("/", "./frontend/dist").index_file("index.html"))
            .default_service(web::route().to(|| async {
                HttpResponse::Ok().content_type("text/html").body(
                    std::fs::read_to_string("./frontend/dist/index.html").unwrap()
                )
            }))
    })
        .bind(server_addr)?
        .run()
        .await
}