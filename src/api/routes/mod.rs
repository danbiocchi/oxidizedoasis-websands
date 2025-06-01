
pub mod user_routes;
pub mod admin;
pub mod health; // Added health module

pub use admin::configure as configure_admin_routes;

pub mod route_config {
    use actix_web::web;
    use log::debug;
    use super::{user_routes, health, configure_admin_routes}; // Added health module to use statement

    pub fn configure_all(cfg: &mut web::ServiceConfig) {
        debug!("Configuring all routes");
        user_routes::configure(cfg);
        health::configure(cfg); // Added health route configuration
        debug!("User and health routes configured, now configuring admin routes");
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

