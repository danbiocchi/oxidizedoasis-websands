use actix_web::web;

pub mod user_routes;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    user_routes::configure(cfg);
}

pub mod configure_routes {
    use actix_web::web;

    pub fn public_routes(cfg: &mut web::ServiceConfig) {
        // Configure public routes
    }

    pub fn protected_routes(cfg: &mut web::ServiceConfig) {
        // Configure protected routes
    }

    pub fn admin_routes(cfg: &mut web::ServiceConfig) {
        // Configure admin routes
    }
}