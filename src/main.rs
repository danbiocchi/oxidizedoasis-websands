use actix_web::{web, App, HttpServer, HttpResponse, http};
use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::migrate::MigrateDatabase;
use log::{info, debug, error, warn};
use dotenv::dotenv;
use actix_files as fs;
use actix_cors::Cors;
use actix_web_httpauth::middleware::HttpAuthentication;
use env_logger::Env;
use serde_json;
use actix_governor::{Governor, GovernorConfigBuilder};
use std::env;
use crate::middleware::validator;
use crate::handlers::admin::admin_validator;
use crate::middleware::cors_logger::CorsLogger;

mod handlers;
mod models;
mod auth;
mod email;
mod middleware;
mod validation;

async fn setup_database(database_url: &str, run_migrations: bool) -> Result<sqlx::Pool<Postgres>, sqlx::Error> {
    if !Postgres::database_exists(database_url).await? {
        info!("Creating database");
        Postgres::create_database(database_url).await?;
    }

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

    if run_migrations {
        info!("Running database migrations");
        sqlx::migrate!("./migrations").run(&pool).await?;
        info!("Migrations completed successfully");
    } else {
        warn!("Skipping database migrations. Make sure your database schema is up to date.");
    }

    Ok(pool)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("Starting OxidizedOasis-WebSands application");

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in environment variables");

    let run_migrations = env::var("RUN_MIGRATIONS")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true);

    let pool = match setup_database(&database_url, run_migrations).await {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to set up database: {:?}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    };

    let host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_string());
    let server_addr = format!("{}:{}", host, port);

    debug!("Server will be listening on: {}", server_addr);

    let governor_conf = GovernorConfigBuilder::default()
        .per_second(2)
        .burst_size(5)
        .finish()
        .unwrap();

    let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
    let allowed_origin = match environment.as_str() {
        "production" => env::var("PRODUCTION_URL").expect("PRODUCTION_URL must be set in production"),
        "development" => env::var("DEVELOPMENT_URL").expect("DEVELOPMENT_URL must be set for development"),
        _ => panic!("ENVIRONMENT must be set to either 'production' or 'development'"),
    };

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&allowed_origin)
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT, http::header::CONTENT_TYPE])
            .max_age(3600);

        let auth = HttpAuthentication::bearer(validator);
        let admin_auth = HttpAuthentication::bearer(admin_validator);

        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(CorsLogger)  // Add this line
            .wrap(cors)
            .wrap(actix_web::middleware::Logger::default())
            .service(
                web::scope("/users")
                    .wrap(Governor::new(&governor_conf))
                    .route("/register", web::post().to(handlers::user::create_user))
                    .route("/login", web::post().to(handlers::user::login_user))
                    .route("/verify", web::get().to(handlers::user::verify_email))
            )
            .service(
                web::scope("/api")
                    .wrap(auth)
                    .service(handlers::user::get_user)
                    .service(handlers::user::update_user)
                    .service(handlers::user::delete_user)
            )
            .service(
                web::scope("/admin")
                    .wrap(admin_auth)
                    .route("/dashboard", web::get().to(handlers::admin::admin_dashboard))
            )
            .service(fs::Files::new("/css", "./static/css").show_files_listing())
            .service(fs::Files::new("/", "./static").index_file("index.html"))
            .default_service(web::route().to(|req: actix_web::HttpRequest| async move {
                error!("Unhandled request: {:?}", req);
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Not Found",
                    "message": "The requested resource could not be found."
                }))
            }))
    })
        .bind(server_addr)?
        .run()
        .await
}