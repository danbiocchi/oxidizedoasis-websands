use actix_web::web;

pub mod user_routes;
pub mod admin;

pub use admin::configure as configure_admin_routes;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    user_routes::configure(cfg);
}

pub mod configure_routes {
    use actix_web::web;
    use super::user_routes;

    pub fn public_routes(cfg: &mut web::ServiceConfig) {
        user_routes::configure_public_routes(cfg);
    }

    pub fn protected_routes(cfg: &mut web::ServiceConfig) {
        user_routes::configure_protected_routes(cfg);
    }

    pub fn admin_routes(cfg: &mut web::ServiceConfig) {
        // Configure admin routes (empty for now)
        cfg.service(web::scope("")); // Placeholder for admin routes
    }
}