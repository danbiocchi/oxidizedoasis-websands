use actix_governor::{GovernorConfigBuilder, GovernorMiddleware};
use actix_web::dev::{ServiceRequest, ServiceResponse};

// Function to create and return a GovernorMiddleware instance
pub fn configure_rate_limit() -> GovernorMiddleware<String, ServiceRequest, ServiceResponse> {
    let governor_conf = GovernorConfigBuilder::default()
        .seconds_per_request(1) // Set the rate limit to 1 request per second
        .burst_size(5)
        .finish()
        .unwrap();

    // Return a new GovernorMiddleware instance
    GovernorMiddleware::new(governor_conf)
}
