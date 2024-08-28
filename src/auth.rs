use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use uuid::Uuid;
use log::{debug, error};

/// Represents the claims in a JWT token
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,  // Subject (user ID)
    pub exp: i64,   // Expiration time
    pub iat: i64,   // Issued at
}

/// Create a new JWT token for a user
///
/// # Arguments
/// * `user_id` - The ID of the user
/// * `secret` - The secret key used to sign the token
///
/// # Returns
/// * `Result<String, jsonwebtoken::errors::Error>` - The JWT token if successful, or an error
pub fn create_jwt(user_id: Uuid, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user_id,
        exp: expiration,
        iat: Utc::now().timestamp(),
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
}

/// Validate a JWT token
///
/// # Arguments
/// * `token` - The JWT token to validate
/// * `secret` - The secret key used to sign the token
///
/// # Returns
/// * `Result<Claims, jsonwebtoken::errors::Error>` - The claims if the token is valid, or an error
pub fn validate_jwt(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    debug!("Attempting to validate JWT");
    let validation = Validation::default();
    match decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation) {
        Ok(token_data) => {
            debug!("JWT validated successfully");
            Ok(token_data.claims)
        },
        Err(e) => {
            error!("JWT validation failed: {:?}", e);
            Err(e)
        }
    }
}