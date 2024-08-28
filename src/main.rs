use actix_web::{web, App, HttpServer, HttpResponse, http};
use sqlx::postgres::PgPoolOptions;
use log::{info, debug, error};
use dotenv::dotenv;
use actix_files as fs;
use actix_cors::Cors;
use actix_web_httpauth::middleware::HttpAuthentication;
use env_logger::Env;

mod handlers;
mod models;
mod auth;
mod email;
mod middleware;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    info!("Starting OxidizedOasis-WebSands application");

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in environment variables");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create database connection pool");

    let host = std::env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_string());
    let server_addr = format!("{}:{}", host, port);

    debug!("Server will be listening on: {}", server_addr);

    HttpServer::new(move || {
        debug!("Configuring HTTP server");
        let auth = HttpAuthentication::bearer(crate::middleware::validator);

        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(
                Cors::default()
                    .allowed_origin("http://127.0.0.1:8080")
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                    .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT, http::header::CONTENT_TYPE])
                    .max_age(3600)
            )
            .wrap(actix_web::middleware::Logger::default())
            .service(
                web::scope("/users")
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
            .service(fs::Files::new("/", "./static").index_file("index.html"))
            .default_service(web::route().to(|req: actix_web::HttpRequest| async move {
                error!("Unhandled request: {:?}", req);
                HttpResponse::NotFound().body("Not Found")
            }))
    })
        .bind(server_addr)?
        .run()
        .await
}