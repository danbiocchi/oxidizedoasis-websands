// src/core/auth/service.rs
use sqlx::PgPool;
use bcrypt::verify;
use crate::common::{
    error::{AuthError, AuthErrorType},
    validation::LoginInput,
};
use crate::core::user::{User, UserRepository};
use super::jwt::{create_jwt, validate_jwt, refresh_access_token, Claims, TokenType, TokenPair, create_token_pair};
use log::{info, warn};

pub struct AuthService {
    user_repository: UserRepository,
    jwt_secret: String,
}

impl AuthService {
    pub fn new(pool: PgPool, jwt_secret: String) -> Self {
        Self {
            user_repository: UserRepository::new(pool),
            jwt_secret,
        }
    }

    /// Login a user and generate a token pair (access token + refresh token)
    pub async fn login(&self, input: LoginInput) -> Result<(TokenPair, User), AuthError> {
        // Find user
        let user = self.user_repository.find_by_username(&input.username)
            .await
            .map_err(|_| AuthError::new(AuthErrorType::InvalidCredentials))?
            .ok_or_else(|| AuthError::new(AuthErrorType::InvalidCredentials))?;

        // Check email verification
        if !user.is_email_verified {
            return Err(AuthError::new(AuthErrorType::EmailNotVerified));
        }

        // Verify password
        if !verify(&input.password, &user.password_hash)
            .map_err(|_| AuthError::new(AuthErrorType::InvalidCredentials))? {
            return Err(AuthError::new(AuthErrorType::InvalidCredentials));
        }

        // Generate token pair with user role
        info!("Generating token pair for user: {}", user.id);
        let token_pair = create_token_pair(user.id, user.role.clone(), &self.jwt_secret)
            .map_err(|e| {
                warn!("Failed to create token pair: {:?}", e);
                AuthError::new(AuthErrorType::InvalidToken)
            })?;

        Ok((token_pair, user))
    }

    /// Validate an access token
    pub async fn validate_auth(&self, token: &str) -> Result<Claims, AuthError> {
        // Validate the token
        let claims = match validate_jwt(token, &self.jwt_secret, Some(TokenType::Access)).await {
            Ok(claims) => claims,
            Err(e) => {
                warn!("Token validation failed: {:?}", e);
                return Err(AuthError::new(AuthErrorType::InvalidToken));
            }
        };

        // Verify the user exists and is verified
        let user = self.user_repository.find_by_id(claims.sub)
            .await
            .map_err(|_| AuthError::new(AuthErrorType::InvalidToken))?
            .ok_or_else(|| AuthError::new(AuthErrorType::InvalidToken))?;

        if !user.is_email_verified {
            return Err(AuthError::new(AuthErrorType::EmailNotVerified));
        }

        Ok(claims)
    }
    
    /// Refresh an access token using a refresh token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<String, AuthError> {
        // Validate the refresh token and get a new access token
        let new_access_token = match refresh_access_token(refresh_token, &self.jwt_secret).await {
            Ok(token) => token,
            Err(e) => {
                warn!("Token refresh failed: {:?}", e);
                return Err(AuthError::new(AuthErrorType::InvalidToken));
            }
        };
            
        // We could add additional checks here, such as checking if the user still exists
        // or if their permissions have changed
            
        Ok(new_access_token)
    }
    
    /// Logout a user by invalidating their tokens
    /// This is a placeholder for a more robust implementation that would
    /// add the tokens to a blacklist or revocation list
    pub async fn logout(&self, access_token: &str, refresh_token: Option<&str>) -> Result<(), AuthError> {
        // Validate the access token to get the user ID
        let access_claims = match validate_jwt(access_token, &self.jwt_secret, Some(TokenType::Access)).await {
            Ok(claims) => claims,
            Err(e) => {
                warn!("Failed to validate access token during logout: {:?}", e);
                return Err(AuthError::new(AuthErrorType::InvalidToken));
            }
        };
        
        // Get the token revocation service using a raw pointer to avoid shared reference to mutable static
        let token_revocation_service = unsafe {
            let service_ptr = &raw const super::jwt::TOKEN_REVOCATION_SERVICE;
            if let Some(service) = &*service_ptr {
                service
            } else {
                warn!("Token revocation service not initialized");
                return Ok(());
            }
        };
        
        // Revoke the access token
        if let Err(e) = token_revocation_service.revoke_token(
            &access_claims.jti,
            access_claims.sub,
            TokenType::Access,
            chrono::DateTime::<chrono::Utc>::from_utc(
                chrono::NaiveDateTime::from_timestamp_opt(access_claims.exp, 0)
                    .unwrap_or_else(|| chrono::Utc::now().naive_utc()),
                chrono::Utc,
            ),
            Some("User logout")
        ).await {
            warn!("Failed to revoke access token: {:?}", e);
            // Continue even if access token revocation fails
        }
        
        // Revoke the refresh token if provided
        if let Some(refresh_token) = refresh_token {
            // Validate the refresh token
            match validate_jwt(refresh_token, &self.jwt_secret, Some(TokenType::Refresh)).await {
                Ok(refresh_claims) => {
                    // Revoke the refresh token
                    if let Err(e) = token_revocation_service.revoke_token(
                        &refresh_claims.jti,
                        refresh_claims.sub,
                        TokenType::Refresh,
                        chrono::DateTime::<chrono::Utc>::from_utc(
                            chrono::NaiveDateTime::from_timestamp_opt(refresh_claims.exp, 0)
                                .unwrap_or_else(|| chrono::Utc::now().naive_utc()),
                            chrono::Utc,
                        ),
                        Some("User logout")
                    ).await {
                        warn!("Failed to revoke refresh token: {:?}", e);
                        // Continue even if refresh token revocation fails
                    }
                },
                Err(e) => {
                    warn!("Failed to validate refresh token during logout: {:?}", e);
                    // Continue even if refresh token validation fails
                }
            }
        }
        
        info!("User {} logged out successfully", access_claims.sub);
        Ok(())
    }
}
