// src/core/auth/service.rs
use sqlx::PgPool;
use bcrypt::verify;
use crate::common::{
    error::{AuthError, AuthErrorType},
    validation::LoginInput,
};
use crate::core::user::{User, UserRepository};
use super::jwt::{create_jwt, validate_jwt, Claims};

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

    pub async fn login(&self, input: LoginInput) -> Result<(String, User), AuthError> {
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

        // Generate token
        let token = create_jwt(user.id, &self.jwt_secret)
            .map_err(|_| AuthError::new(AuthErrorType::InvalidToken))?;

        Ok((token, user))
    }

    pub async fn validate_auth(&self, token: &str) -> Result<Claims, AuthError> {
        let claims = validate_jwt(token, &self.jwt_secret)
            .map_err(|_| AuthError::new(AuthErrorType::InvalidToken))?;

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
}
