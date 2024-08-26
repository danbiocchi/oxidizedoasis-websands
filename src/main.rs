use actix_web::{web, App, HttpServer};
use actix_files as fs;
use actix_cors::Cors;
use sqlx::postgres::PgPoolOptions;
use dotenv::dotenv;
use std::env;
use log::{info, error};
use actix_web_httpauth::middleware::HttpAuthentication;

mod models;
mod handlers;
mod config;
mod auth;
mod middleware;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    info!("Attempting to connect to database: {}", database_url);

    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
    {
        Ok(pool) => {
            info!("Successfully connected to the database");
            pool
        },
        Err(e) => {
            error!("Failed to connect to the database: {:?}", e);
            panic!("Database connection error");
        }
    };

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        let auth = HttpAuthentication::bearer(middleware::validator);

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .service(handlers::create_user)
            .service(handlers::login_user)
            .service(
                web::scope("/api")
                    .wrap(auth)
                    .service(handlers::get_user)
                    .service(handlers::update_user)
                    .service(handlers::delete_user)
            )
            .service(fs::Files::new("/", "./static").index_file("index.html"))
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}