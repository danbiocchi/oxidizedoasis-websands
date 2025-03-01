use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use uuid::Uuid;
use log::{debug, error, info, warn};
use std::env;
use std::sync::Arc;
use crate::core::auth::token_revocation::TokenRevocationService;

/// JWT Claims structure with enhanced security
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: Uuid,        // Subject (user ID)
    pub exp: i64,         // Expiration time
    pub iat: i64,         // Issued at time
    pub nbf: i64,         // Not valid before time
    pub jti: String,      // JWT ID (unique identifier for this token)
    pub role: String,     // User role
    pub token_type: TokenType, // Token type (access or refresh)
}

/// Token types to distinguish between access and refresh tokens
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TokenType {
    Access,
    Refresh,
}

/// Token pair containing both access and refresh tokens
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

/// Get token expiration time based on token type and environment configuration
fn get_token_expiration(token_type: &TokenType) -> i64 {
    let now = Utc::now();
    
    match token_type {
        TokenType::Access => {
            // Default to 30 minutes, but allow configuration via environment variable
            let minutes = env::var("JWT_ACCESS_TOKEN_EXPIRATION_MINUTES")
                .unwrap_or_else(|_| "30".to_string())
                .parse::<i64>()
                .unwrap_or(30);
                
            now.checked_add_signed(Duration::minutes(minutes))
                .expect("valid timestamp")
                .timestamp()
        },
        TokenType::Refresh => {
            // Default to 7 days, but allow configuration via environment variable
            let days = env::var("JWT_REFRESH_TOKEN_EXPIRATION_DAYS")
                .unwrap_or_else(|_| "7".to_string())
                .parse::<i64>()
                .unwrap_or(7);
                
            now.checked_add_signed(Duration::days(days))
                .expect("valid timestamp")
                .timestamp()
        }
    }
}

/// Create a new JWT token for a user
///
/// # Arguments
/// * `user_id` - The ID of the user
/// * `role` - The user's role
/// * `secret` - The secret key used to sign the token
/// * `token_type` - The type of token (access or refresh)
///
/// # Returns
/// * `Result<String, jsonwebtoken::errors::Error>` - The JWT token if successful, or an error
pub fn create_jwt(
    user_id: Uuid,
    role: String,
    secret: &str,
    token_type: TokenType
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let expiration = get_token_expiration(&token_type);
    
    // Generate a unique token ID
    let jti = Uuid::new_v4().to_string();
    
    let claims = Claims {
        sub: user_id,
        exp: expiration,
        iat: now,
        nbf: now,  // Token is valid immediately
        jti,
        role,
        token_type: token_type.clone(),
    };

    info!("Creating {} token for user {} with expiration in {} seconds",
          if token_type == TokenType::Access { "access" } else { "refresh" },
          user_id,
          expiration - now);

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    ).map_err(|e| {
        error!("Failed to create JWT: {:?}", e);
        e
    })
}

/// Create a token pair (access token + refresh token)
///
/// # Arguments
/// * `user_id` - The ID of the user
/// * `role` - The user's role
/// * `secret` - The secret key used to sign the tokens
///
/// # Returns
/// * `Result<TokenPair, jsonwebtoken::errors::Error>` - The token pair if successful, or an error
pub fn create_token_pair(
    user_id: Uuid,
    role: String,
    secret: &str
) -> Result<TokenPair, jsonwebtoken::errors::Error> {
    let access_token = create_jwt(user_id, role.clone(), secret, TokenType::Access)?;
    let refresh_token = create_jwt(user_id, role, secret, TokenType::Refresh)?;
    
    Ok(TokenPair {
        access_token,
        refresh_token,
    })
}

/// Validate a JWT token
///
/// # Arguments
/// * `token` - The JWT token to validate
/// * `secret` - The secret key used to sign the token
/// * `expected_type` - Optional expected token type (access or refresh)
///
/// # Returns
/// * `Result<Claims, jsonwebtoken::errors::Error>` - The claims if the token is valid, or an error
pub async fn validate_jwt(
    token: &str,
    secret: &str,
    expected_type: Option<TokenType>
) -> Result<Claims, jsonwebtoken::errors::Error> {
    debug!("Attempting to validate JWT");
    
    // Create validation with leeway to account for clock skew
    let mut validation = Validation::default();
    validation.leeway = 60; // 60 seconds of leeway for clock skew
    
    // Decode and validate the token
    match decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation) {
        Ok(token_data) => {
            let claims = token_data.claims;
            
            // If an expected token type is provided, validate it
            if let Some(expected) = expected_type {
                if claims.token_type != expected {
                    error!("Token type mismatch: expected {:?}, got {:?}", expected, claims.token_type);
                    return Err(jsonwebtoken::errors::Error::from(
                        jsonwebtoken::errors::ErrorKind::InvalidToken
                    ));
                }
            }
            
            // Check if the token has been revoked
            if is_token_revoked(&claims.jti).await {
                error!("Token has been revoked: {}", claims.jti);
                return Err(jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken
                ));
            }
            
            debug!("JWT validated successfully for user: {}", claims.sub);
            Ok(claims)
        },
        Err(e) => {
            error!("JWT validation failed: {:?}", e);
            Err(e)
        }
    }
}

// Global token revocation service reference
pub static mut TOKEN_REVOCATION_SERVICE: Option<Arc<TokenRevocationService>> = None;

/// Initialize the token revocation service
/// 
/// This should be called once during application startup
///
/// # Arguments
/// * `service` - The token revocation service
pub fn init_token_revocation(service: Arc<TokenRevocationService>) {
    unsafe {
        TOKEN_REVOCATION_SERVICE = Some(service);
    }
}

/// Check if a token is in the revocation list
/// 
/// # Arguments
/// * `jti` - The JWT ID to check
///
/// # Returns
/// * `bool` - True if the token is revoked, false otherwise
pub async fn is_token_revoked(jti: &str) -> bool {
    unsafe {
        // Use raw pointer to avoid shared reference to mutable static
        let service_ptr = &raw const TOKEN_REVOCATION_SERVICE;
        if let Some(service) = &*service_ptr {
            match service.is_token_revoked(jti).await {
                Ok(is_revoked) => is_revoked,
                Err(e) => {
                    error!("Error checking token revocation: {:?}", e);
                    // If there's an error checking revocation status,
                    // assume the token is not revoked to prevent service disruption
                    false
                }
            }
        } else {
            // If the service isn't initialized, assume tokens are not revoked
            warn!("Token revocation service not initialized");
            false
        }
    }
}

/// Refresh an access token using a valid refresh token
///
/// # Arguments
/// * `refresh_token` - The refresh token
/// * `secret` - The secret key used to sign the tokens
///
/// # Returns
/// * `Result<String, jsonwebtoken::errors::Error>` - A new access token if successful, or an error
pub async fn refresh_access_token(
    refresh_token: &str,
    secret: &str
) -> Result<String, jsonwebtoken::errors::Error> {
    // Validate the refresh token
    let validation_result = validate_jwt(refresh_token, secret, Some(TokenType::Refresh)).await;
    let claims = match validation_result {
        Ok(claims) => claims,
        Err(e) => return Err(e),
    };
    
    // Create a new access token
    create_jwt(claims.sub, claims.role, secret, TokenType::Access)
}

// Tests removed for simplicity