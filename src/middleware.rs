use actix_web::error::ErrorUnauthorized;
use actix_web::{dev::ServiceRequest, Error};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use crate::auth;

pub async fn validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = credentials.token();

    match auth::validate_jwt(token, &jwt_secret) {
        Ok(_claims) => Ok(req),
        Err(_) => Err((ErrorUnauthorized("Invalid token"), req)),
    }
}