use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, errors::Error as JwtError, errors::ErrorKind as JwtErrorKind};
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
pub fn create_jwt(user_id: Uuid, secret: &str) -> Result<String, JwtError> {
    if secret.is_empty() {
        return Err(JwtError::from(JwtErrorKind::InvalidToken));
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_create_jwt_success() {
        let user_id = Uuid::new_v4();
        let secret = "test_secret";
        let token = create_jwt(user_id, secret).expect("Failed to create JWT");
        assert!(!token.is_empty(), "JWT token should not be empty");
    }

    #[test]
    fn test_validate_jwt_success() {
        let user_id = Uuid::new_v4();
        let secret = "test_secret";
        let token = create_jwt(user_id, secret).expect("Failed to create JWT");
        let claims = validate_jwt(&token, secret).expect("Failed to validate JWT");
        assert_eq!(claims.sub, user_id, "User ID in claims should match the original");
    }

    #[test]
    fn test_jwt_expiration() {
        let user_id = Uuid::new_v4();
        let secret = "test_secret";
        let token = create_jwt(user_id, secret).expect("Failed to create JWT");

        // Wait for 2 seconds to ensure the token is still valid
        sleep(StdDuration::from_secs(2));
        let result = validate_jwt(&token, secret);
        assert!(result.is_ok(), "Token should still be valid");

        // Note: Testing actual expiration would require mocking time or a longer wait,
        // which is not practical for unit tests. In a real scenario, you might use
        // a time mocking library to test expiration without waiting.
    }

    #[test]
    fn test_validate_jwt_with_invalid_secret() {
        let user_id = Uuid::new_v4();
        let secret = "correct_secret";
        let token = create_jwt(user_id, secret).expect("Failed to create JWT");
        let wrong_secret = "wrong_secret";
        let result = validate_jwt(&token, wrong_secret);
        assert!(result.is_err(), "Validation should fail with incorrect secret");
    }

    #[test]
    fn test_validate_jwt_with_invalid_token() {
        let secret = "test_secret";
        let invalid_token = "invalid.token.string";
        let result = validate_jwt(invalid_token, secret);
        assert!(result.is_err(), "Validation should fail with invalid token");
    }

    #[test]
    fn test_create_jwt_with_empty_secret() {
        let user_id = Uuid::new_v4();
        let secret = "";
        let result = create_jwt(user_id, secret);
        assert!(result.is_err(), "JWT creation should fail with empty secret");
    }

    #[test]
    fn test_claims_content() {
        let user_id = Uuid::new_v4();
        let secret = "test_secret";
        let token = create_jwt(user_id, secret).expect("Failed to create JWT");
        let claims = validate_jwt(&token, secret).expect("Failed to validate JWT");

        assert_eq!(claims.sub, user_id, "User ID should match");
        let now = Utc::now().timestamp();
        assert!(claims.iat <= now, "Issued at should be in the past or now");
        assert!(claims.exp > now, "Expiration should be in the future");
        assert!(claims.exp <= now + 24 * 3600, "Expiration should be within 24 hours");
    }
}