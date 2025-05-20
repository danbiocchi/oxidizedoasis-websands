
pub mod user_routes;
pub mod admin;

pub use admin::configure as configure_admin_routes;

pub mod route_config {
    use actix_web::web;
    use log::debug;
    use super::{user_routes, configure_admin_routes};

    pub fn configure_all(cfg: &mut web::ServiceConfig) {
        debug!("Configuring all routes");
        user_routes::configure(cfg);
        debug!("User routes configured, now configuring admin routes");
        configure_admin_routes(cfg);
        debug!("All routes configured");
    }

    pub fn public_routes(cfg: &mut web::ServiceConfig) {
        user_routes::configure_public_routes(cfg);
    }

    pub fn protected_routes(cfg: &mut web::ServiceConfig) {
        user_routes::configure_protected_routes(cfg);
    }

    pub fn admin_routes(cfg: &mut web::ServiceConfig) {
        configure_admin_routes(cfg);
    }
}

