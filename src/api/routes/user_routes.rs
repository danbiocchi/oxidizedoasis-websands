use actix_web::web;
use crate::api::handlers::user_handler;
use actix_web_httpauth::middleware::HttpAuthentication;
use crate::infrastructure::middleware::auth::jwt_auth_validator;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/register", web::post().to(user_handler::create_user_handler))
            .route("/login", web::post().to(user_handler::login_user_handler))
            .route("/verify", web::get().to(user_handler::verify_email_handler))
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
