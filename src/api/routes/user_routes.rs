use actix_web::web;
use actix_governor::{Governor, GovernorConfigBuilder};
use crate::api::handlers::user_handler;
use actix_web_httpauth::middleware::HttpAuthentication;
use crate::infrastructure::middleware::auth::jwt_auth_validator;

pub fn configure(cfg: &mut web::ServiceConfig) {
    // Rate limit configuration for auth endpoints
    let auth_governor_config = GovernorConfigBuilder::default()
        .seconds_per_request(1) // 2 requests per second
        .burst_size(5) // Allow bursts of up to 5 requests
        .finish()
        .unwrap();

    cfg.service(
        web::scope("/users")
            // Public routes with rate limiting only on login
            .service(
                web::scope("/login")
                    .wrap(Governor::new(&auth_governor_config))
                    .route("", web::post().to(user_handler::login_user_handler))
            )
            // Register and verify without rate limiting
            .route("/register", web::post().to(user_handler::create_user_handler))
            .route("/verify", web::get().to(user_handler::verify_email_handler))
            // Protected routes with authentication
            .service(
                web::scope("")
                    .wrap(HttpAuthentication::bearer(jwt_auth_validator))
                    .route("/me", web::get().to(user_handler::get_current_user_handler))
                    .route("/{id}", web::get().to(user_handler::get_user_handler))
                    .route("/{id}", web::put().to(user_handler::update_user_handler))
                    .route("/{id}", web::delete().to(user_handler::delete_user_handler))
            )
    );
}

// Public routes configuration
pub fn configure_public_routes(cfg: &mut web::ServiceConfig) {
    // Rate limit configuration for login
    let auth_governor_config = GovernorConfigBuilder::default()
        .per_second(2)
        .burst_size(5)
        .finish()
        .unwrap();

    cfg.service(
        web::scope("")
            // Login with rate limiting
            .service(
                web::scope("/login")
                    .wrap(Governor::new(&auth_governor_config))
                    .route("", web::post().to(user_handler::login_user_handler))
            )
            // Register and verify without rate limiting
            .route("/register", web::post().to(user_handler::create_user_handler))
            .route("/verify", web::get().to(user_handler::verify_email_handler))
    );
}

// Protected routes configuration
pub fn configure_protected_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/me", web::get().to(user_handler::get_current_user_handler))
            .route("/{id}", web::get().to(user_handler::get_user_handler))
            .route("/{id}", web::put().to(user_handler::update_user_handler))
            .route("/{id}", web::delete().to(user_handler::delete_user_handler))
    );
}