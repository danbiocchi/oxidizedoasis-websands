use actix_web::web;
use crate::api::handlers::user_handler;
use actix_web_httpauth::middleware::HttpAuthentication;
use crate::infrastructure::middleware::{jwt_auth_validator, CookieAuth};
use crate::infrastructure::middleware::csrf::CsrfProtection;
use crate::infrastructure::middleware::rate_limit::RateLimiter;

pub fn configure(cfg: &mut web::ServiceConfig) {
    // Configure public auth routes (no /api prefix)
    cfg.service(
        web::scope("/users")
            .wrap(RateLimiter::new())
            .route("/login", web::post().to(user_handler::login_user_handler))
            .route("/register", web::post().to(user_handler::create_user_handler))
            .route("/verify", web::get().to(user_handler::verify_email_handler))
            .route("/refresh", web::post().to(user_handler::refresh_token_handler))
            .route("/refresh/cookie", web::get().to(user_handler::refresh_token_from_cookie_handler))
            .service(
                web::scope("/password-reset")
                    .route("/verify", web::get().to(user_handler::verify_reset_token_handler))
                    .route("/request", web::post().to(user_handler::request_password_reset_handler))
                    .route("/reset", web::post().to(user_handler::reset_password_handler))
            )
    );

    // Configure protected API routes with bearer token authentication
    cfg.service(
        web::scope("/api/users")
            .wrap(HttpAuthentication::bearer(jwt_auth_validator))
            .route("/me", web::get().to(user_handler::get_current_user_handler))
            .route("/logout", web::post().to(user_handler::logout_user_handler))
            .route("/{id}", web::get().to(user_handler::get_user_handler))
            .route("/{id}", web::put().to(user_handler::update_user_handler))
            .route("/{id}", web::delete().to(user_handler::delete_user_handler))
    );

    // Configure cookie-based protected API routes
    cfg.service(
        web::scope("/api/cookie/users")
            .wrap(CookieAuth::new())
            .wrap(CsrfProtection)
            .route("/me", web::get().to(user_handler::get_current_user_from_cookie_handler))
            .route("/logout", web::post().to(user_handler::logout_user_handler))
            .route("/refresh", web::get().to(user_handler::refresh_token_from_cookie_handler))
            .route("/{id}", web::get().to(user_handler::get_user_handler))
            .route("/{id}", web::put().to(user_handler::update_user_handler))
            .route("/{id}", web::delete().to(user_handler::delete_user_handler))
    );
}

// Public routes configuration 
#[allow(dead_code)]
pub fn configure_public_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .wrap(RateLimiter::new())
            .route("/login", web::post().to(user_handler::login_user_handler))
            .route("/register", web::post().to(user_handler::create_user_handler))
            .route("/verify", web::get().to(user_handler::verify_email_handler))
            .route("/refresh/cookie", web::get().to(user_handler::refresh_token_from_cookie_handler))
            .route("/refresh", web::post().to(user_handler::refresh_token_handler))
            .service(
                web::scope("/password-reset")
                    .route("/verify", web::get().to(user_handler::verify_reset_token_handler))
                    .route("/request", web::post().to(user_handler::request_password_reset_handler))
                    .route("/reset", web::post().to(user_handler::reset_password_handler))
            )
    );
}

// Protected routes configuration
#[allow(dead_code)]
pub fn configure_protected_routes(cfg: &mut web::ServiceConfig) {
    // Bearer token authentication routes
    cfg.service(
        web::scope("/api/users")
            .wrap(HttpAuthentication::bearer(jwt_auth_validator))
            .route("/me", web::get().to(user_handler::get_current_user_handler))
            .route("/logout", web::post().to(user_handler::logout_user_handler))
            .route("/{id}", web::get().to(user_handler::get_user_handler))
            .route("/{id}", web::put().to(user_handler::update_user_handler))
            .route("/{id}", web::delete().to(user_handler::delete_user_handler))
    );

    // Cookie-based authentication routes
    cfg.service(
        web::scope("/api/cookie/users")
            .wrap(CookieAuth::new())
            .wrap(CsrfProtection)
            .route("/me", web::get().to(user_handler::get_current_user_from_cookie_handler))
            .route("/logout", web::post().to(user_handler::logout_user_handler))
            .route("/refresh", web::get().to(user_handler::refresh_token_from_cookie_handler))
            .route("/{id}", web::get().to(user_handler::get_user_handler))
            .route("/{id}", web::put().to(user_handler::update_user_handler))
            .route("/{id}", web::delete().to(user_handler::delete_user_handler))
    );
}
