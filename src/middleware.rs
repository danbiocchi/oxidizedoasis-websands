use actix_web::error::ErrorUnauthorized;
use actix_web::{dev::ServiceRequest, Error};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use crate::auth;
use log::{error, debug, info};

pub async fn validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = credentials.token();

    debug!("Received request with token: {}", token);

    match auth::validate_jwt(token, &jwt_secret) {
        Ok(claims) => {
            info!("Token validated successfully for user: {}", claims.sub);
            Ok(req)
        },
        Err(e) => {
            error!("Token validation failed. Token: {}. Error: {:?}", token, e);
            Err((ErrorUnauthorized("Invalid token"), req))
        },
    }
}
