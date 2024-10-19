use actix_cors::Cors;
use actix_web::http;
use std::env;

pub fn configure_cors() -> Cors {
    let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
    let allowed_origin = match environment.as_str() {
        "production" => env::var("PRODUCTION_URL")
            .expect("PRODUCTION_URL must be set in production"),
        _ => env::var("DEVELOPMENT_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string()),
    };

    Cors::default()
        .allowed_origin(&allowed_origin)
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
        .allowed_headers(vec![
            http::header::AUTHORIZATION,
            http::header::ACCEPT,
            http::header::CONTENT_TYPE,
        ])
        .max_age(3600)
}