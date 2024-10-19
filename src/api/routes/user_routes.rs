use actix_web::web;
use crate::api::handlers::user_handler;
use actix_web_httpauth::middleware::HttpAuthentication;
use crate::infrastructure::middleware::auth::validator;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/register", web::post().to(user_handler::create_user))
            .route("/login", web::post().to(user_handler::login_user))
            .route("/verify", web::get().to(user_handler::verify_email))
            .service(
                web::scope("")
                    .wrap(HttpAuthentication::bearer(validator))
                    .route("/me", web::get().to(user_handler::get_current_user))
                    .route("/{id}", web::get().to(user_handler::get_user))
                    .route("/{id}", web::put().to(user_handler::update_user))
                    .route("/{id}", web::delete().to(user_handler::delete_user))
            )
    );
}