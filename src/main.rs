use std::env;
use std::sync::Arc;
use std::time::Duration;
use actix_files as fs;
use actix_web::{App, HttpResponse, HttpServer, web, middleware};
use dotenv::dotenv;
use env_logger::Env;
use log::{debug, error, info, warn};
use sqlx::postgres::Postgres;

use crate::api::routes::configure_routes;
use crate::api::handlers::user_handler::create_handler as create_user_handler_factory; // Renamed for clarity
use crate::core::email::EmailService;
use crate::core::user::UserRepository;
use crate::core::auth::AuthService;
use crate::core::auth::token_revocation::{TokenRevocationService, TokenRevocationServiceTrait};
use crate::core::auth::active_token::{ActiveTokenService, ActiveTokenServiceTrait};
use crate::infrastructure::{AppConfig, configure_cors, create_pool, RequestLogger, RateLimiter};

mod api;
mod common;
mod core;
mod infrastructure;

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

    if let Err(e) = validate_critical_env_vars() {
        error!("Environment validation failed: {}", e);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
    }

    let config = match AppConfig::from_env() {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {:?}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    };

    let config_clone = config.clone();
    let server_host = config.server.host.clone();
    let server_port = config.server.port.clone();
    let run_migrations = env::var("RUN_MIGRATIONS")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true);

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

    let email_service_arc = Arc::new(EmailService::new());
    let active_token_service_arc: Arc<dyn ActiveTokenServiceTrait> = Arc::new(ActiveTokenService::new(pool.clone()));
    
    let mut token_revocation_service_mut = TokenRevocationService::new(pool.clone());
    token_revocation_service_mut.set_active_token_service(active_token_service_arc.clone());
    let token_revocation_service_arc: Arc<dyn TokenRevocationServiceTrait> = Arc::new(token_revocation_service_mut);
    
    let jwt_secret_main = env::var("JWT_SECRET").expect("JWT_SECRET must be set for main");
    let auth_service_arc = Arc::new(AuthService::new(
        Arc::new(UserRepository::new(pool.clone())),
        jwt_secret_main,
        token_revocation_service_arc.clone(),
        active_token_service_arc.clone()
    ));
    
    let cleanup_revoked_service = token_revocation_service_arc.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); 
        loop {
            interval.tick().await;
            match cleanup_revoked_service.cleanup_expired_tokens().await {
                Ok(count) => {
                    if count > 0 { info!("Cleaned up {} expired revoked tokens", count); }
                },
                Err(e) => { error!("Failed to clean up expired revoked tokens: {:?}", e); }
            }
        }
    });

    let cleanup_active_service = active_token_service_arc.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); 
        loop {
            interval.tick().await;
            match cleanup_active_service.cleanup_expired_tokens().await {
                Ok(count) => {
                    if count > 0 { info!("Cleaned up {} expired active tokens", count); }
                },
                Err(e) => { error!("Failed to clean up expired active tokens: {:?}", e); }
            }
        }
    });
    
    let user_handler_data = web::Data::new(create_user_handler_factory(
        pool.clone(),
        email_service_arc.clone(),
        auth_service_arc.clone(), // Pass AuthService
        token_revocation_service_arc.clone(), // Pass TokenRevocationService
        active_token_service_arc.clone() // Pass ActiveTokenService
    ));

    let server_addr = format!("{}:{}", server_host, server_port);
    debug!("Server will be listening on: {}", server_addr);

    HttpServer::new(move || {
        let app_config_clone = config_clone.clone(); 
        App::new()
            .wrap(RateLimiter::new())
            .wrap(configure_cors())
            .wrap(
                middleware::DefaultHeaders::new()
                    .add(("X-XSS-Protection", "1; mode=block"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
                    .add(("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"))
                    .add(("Cross-Origin-Embedder-Policy", "require-corp"))
                    .add(("Cross-Origin-Opener-Policy", "same-origin"))
                    .add(("Cross-Origin-Resource-Policy", "same-origin"))
                    .add(("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:* wss://127.0.0.1:*; font-src 'self' https://cdnjs.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; worker-src 'self' blob:; upgrade-insecure-requests;"))
            )
            .wrap(RequestLogger::new())
            .wrap(middleware::Compress::default())
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(email_service_arc.clone()))
            .app_data(user_handler_data.clone()) // Add UserHandler
            .app_data(web::Data::new(auth_service_arc.clone())) 
            .app_data(web::Data::new(token_revocation_service_arc.clone())) // Make TRS available
            .app_data(web::Data::new(active_token_service_arc.clone()))   // Make ATS available
            .app_data(web::Data::new(app_config_clone.clone())) 
            .app_data(web::Data::new(UserRepository::new(pool.clone())))
            .app_data(web::JsonConfig::default()
                .limit(4096)
                .error_handler(|err, _| {
                    actix_web::error::InternalError::from_response(
                        err,
                        HttpResponse::BadRequest()
                            .content_type("application/json")
                            .body(r#"{"error":"Invalid JSON payload"}"#),
                    ).into()
                }))
            .service(fs::Files::new("/static/css", "./frontend/static/css").prefer_utf8(true).use_last_modified(true))
            .configure(configure_routes)
            .service(fs::Files::new("/", "./frontend/dist").index_file("index.html").prefer_utf8(true).use_last_modified(true))
            .default_service(web::route().to(|| async {
                match std::fs::read_to_string("./frontend/dist/index.html") {
                    Ok(contents) => HttpResponse::Ok().content_type("text/html; charset=utf-8").append_header(("Cache-Control", "no-store, must-revalidate")).append_header(("Pragma", "no-cache")).append_header(("Expires", "0")).body(contents),
                    Err(e) => {
                        error!("Failed to read index.html: {}", e); 
                        HttpResponse::InternalServerError().content_type("application/json").body(r#"{"error": "An unexpected error occurred"}"#) 
                    }
                }
            }))
    })
        .keep_alive(Duration::from_secs(75))
        .client_request_timeout(Duration::from_secs(60))
        .server_hostname(server_host)
        .backlog(1024)
        .workers(num_cpus::get() * 2)
        .shutdown_timeout(30)
        .bind(&server_addr)?
        .run()
        .await
}
