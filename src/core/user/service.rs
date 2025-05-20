// src/core/user/service.rs
use std::sync::Arc;
use bcrypt::{hash, DEFAULT_COST};
use uuid::Uuid;
use log::{debug, error, info};
use chrono::Utc;

use crate::common::{
    error::{ApiError, ApiErrorType, DbError},
    utils::generate_secure_token,
    validation::{UserInput, validate_and_sanitize_user_input, validate_password},
};
use crate::core::email::EmailServiceTrait;
use crate::core::auth::token_revocation::TokenRevocationServiceTrait; // Added
use super::{User, UserRepository};

pub struct UserService {
    repository: UserRepository,
    email_service: Arc<dyn EmailServiceTrait>,
    token_revocation_service: Arc<dyn TokenRevocationServiceTrait>, // Added
}

impl UserService {
    pub fn new(
        repository: UserRepository,
        email_service: Arc<dyn EmailServiceTrait>,
        token_revocation_service: Arc<dyn TokenRevocationServiceTrait>, // Added
    ) -> Self {
        Self {
            repository,
            email_service,
            token_revocation_service, // Added
        }
    }

    pub async fn create_user(&self, input: UserInput) -> Result<(User, String), ApiError> {
        debug!("Creating new user with username: {}", input.username);

        let validated_input = validate_and_sanitize_user_input(input)
            .map_err(|_| ApiError::new("Invalid input", ApiErrorType::Validation))?;

        let password_hash = if let Some(ref password) = validated_input.password {
            Some(hash(password.as_bytes(), DEFAULT_COST)
                .map_err(|e| {
                    error!("Failed to hash password: {}", e);
                    ApiError::new("Failed to process password", ApiErrorType::Internal)
                })?)
        } else {
            debug!("Password not provided for new user");
            return Err(ApiError::new("Password is required", ApiErrorType::Validation));
        };

        let verification_token = generate_secure_token();
        let token_for_email = verification_token.clone();
        let token_for_return = verification_token.clone();

        let user = self.repository.create(
            &validated_input,
            password_hash.unwrap(),
            verification_token
        )
            .await
            .map_err(|e| {
                error!("Database error while creating user: {}", e);
                ApiError::from(DbError::from(e))
            })?;

        if let Some(email) = &user.email {
            debug!("Sending verification email to: {}", email);
            if let Err(e) = self.email_service.send_verification_email(email, &token_for_email).await {
                error!("Failed to send verification email: {}", e);
            }
        }

        info!("Successfully created user: {}", user.id);
        Ok((user, token_for_return))
    }

    pub async fn verify_email(&self, token: &str) -> Result<(), ApiError> {
        debug!("Attempting to verify email with token");
        match self.repository.verify_email(token).await {
            Ok(Some(_)) => {
                info!("Successfully verified email with token");
                Ok(())
            },
            Ok(None) => {
                debug!("No matching token found or token expired");
                Err(ApiError::new(
                    "Invalid or expired verification token",
                    ApiErrorType::Validation
                ))
            },
            Err(e) => {
                error!("Database error while verifying email: {}", e);
                Err(ApiError::from(DbError::from(e)))
            }
        }
    }

    pub async fn get_user_by_id(&self, id: Uuid) -> Result<User, ApiError> {
        debug!("Looking up user by id: {}", id);
        self.repository.find_by_id(id)
            .await
            .map_err(|e| ApiError::from(DbError::from(e)))?
            .ok_or_else(|| {
                debug!("User not found: {}", id);
                ApiError::new("User not found", ApiErrorType::NotFound)
            })
    }

    pub async fn update_user(&self, id: Uuid, input: UserInput) -> Result<User, ApiError> {
        debug!("Updating user: {}", id);
        let validated_input = validate_and_sanitize_user_input(input)
            .map_err(|_| ApiError::new("Invalid input", ApiErrorType::Validation))?;
        
        let password_hash = if let Some(ref password) = validated_input.password {
            Some(hash(password.as_bytes(), DEFAULT_COST)
                .map_err(|e| {
                    error!("Failed to hash password during update: {}", e);
                    ApiError::new("Failed to process password", ApiErrorType::Internal)
                })?)
        } else {
            None
        };

        let updated_user = self.repository.update(id, &validated_input, password_hash.clone())
            .await
            .map_err(|e| {
                error!("Failed to update user {}: {}", id, e);
                ApiError::from(DbError::from(e))
            })?;

        if password_hash.is_some() {
            match self.token_revocation_service.revoke_all_user_tokens(
                id,
                Some("Password changed"),
            ).await {
                Ok(count) => {
                    info!("Revoked {} tokens after password change for user {}", count, id);
                },
                Err(e) => {
                    error!("Failed to revoke tokens after password change: {:?}", e);
                }
            }
        }
        Ok(updated_user)
    }

    pub async fn delete_user(&self, id: Uuid) -> Result<(), ApiError> {
        debug!("Attempting to delete user: {}", id);
        let deleted = self.repository.delete(id)
            .await
            .map_err(|e| {
                error!("Database error while deleting user {}: {}", id, e);
                ApiError::from(DbError::from(e))
            })?;

        if deleted {
            info!("Successfully deleted user: {}", id);
            Ok(())
        } else {
            debug!("No user found to delete: {}", id);
            Err(ApiError::new("User not found", ApiErrorType::NotFound))
        }
    }

    pub async fn check_email_verified(&self, username: &str) -> Result<bool, ApiError> {
        debug!("Checking email verification status for: {}", username);
        self.repository.check_email_verified(username)
            .await
            .map_err(|e| {
                error!("Database error while checking email verification: {}", e);
                ApiError::from(DbError::from(e))
            })
    }

    pub async fn request_password_reset(&self, email: &str) -> Result<(), ApiError> {
        debug!("Processing password reset request for email: {}", email);
        let user = match self.repository.find_user_by_email(email).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                debug!("No user found with email: {}", email);
                return Ok(());
            },
            Err(e) => return Err(ApiError::from(DbError::from(e))),
        };

        if !user.is_email_verified {
            debug!("Attempted password reset for unverified email: {}", email);
            return Err(ApiError::new("Email not verified", ApiErrorType::Validation));
        }

        let reset_token = self.repository.create_password_reset_token(user.id)
            .await
            .map_err(|e| {
                error!("Failed to create password reset token: {}", e);
                ApiError::from(DbError::from(e))
            })?;

        self.email_service.send_password_reset_email(email, &reset_token.token)
            .await
            .map_err(|e| {
                error!("Failed to send password reset email: {}", e);
                ApiError::new("Failed to send password reset email", ApiErrorType::Internal)
            })?;

        info!("Password reset email sent to: {}", email);
        Ok(())
    }

    pub async fn verify_reset_token(&self, token: &str) -> Result<(), ApiError> {
        debug!("Verifying password reset token");
        self.repository.verify_reset_token(token)
            .await
            .map_err(|e| ApiError::from(DbError::from(e)))?
            .ok_or_else(|| {
                debug!("Invalid or expired reset token");
                ApiError::new("Invalid or expired reset token", ApiErrorType::Validation)
            })?;
        Ok(())
    }

    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<(), ApiError> {
        debug!("Processing password reset");
        validate_password(new_password)
            .map_err(|e| {
                debug!("Invalid new password: {}", e);
                ApiError::new(e.to_string(), ApiErrorType::Validation)
            })?;

        let reset_token = self.repository.verify_reset_token(token)
            .await
            .map_err(|e| ApiError::from(DbError::from(e)))?
            .ok_or_else(|| {
                debug!("Invalid or expired reset token");
                ApiError::new("Invalid or expired reset token", ApiErrorType::Validation)
            })?;

        let password_hash = hash(new_password.as_bytes(), DEFAULT_COST)
            .map_err(|e| {
                error!("Failed to hash new password: {}", e);
                ApiError::new("Failed to process password", ApiErrorType::Internal)
            })?;

        self.repository.update_password(reset_token.user_id, &password_hash)
            .await
            .map_err(|e| {
                error!("Failed to update password: {}", e);
                ApiError::from(DbError::from(e))
            })?;

        self.repository.mark_reset_token_used(token)
            .await
            .map_err(|e| {
                error!("Failed to mark reset token as used: {}", e);
                ApiError::from(DbError::from(e))
            })?;

        match self.token_revocation_service.revoke_all_user_tokens(
            reset_token.user_id,
            Some("Password reset"),
        ).await {
            Ok(count) => {
                info!("Revoked {} tokens after password reset for user {}", 
                        count, reset_token.user_id);
            },
            Err(e) => {
                error!("Failed to revoke tokens after password reset: {:?}", e);
            }
        }

        info!("Successfully reset password for user: {}", reset_token.user_id);
        Ok(())
    }

    pub async fn resend_verification_email(&self, user_id: Uuid) -> Result<(), ApiError> {
        debug!("Resending verification email for user: {}", user_id);
        let user = self.get_user_by_id(user_id).await?;

        if user.is_email_verified {
            debug!("Email already verified for user: {}", user_id);
            return Err(ApiError::new("Email already verified", ApiErrorType::Validation));
        }

        let email = user.email.ok_or_else(|| {
            debug!("No email address found for user: {}", user_id);
            ApiError::new("No email address associated with user", ApiErrorType::Validation)
        })?;

        let verification_token = generate_secure_token();

        self.repository.update_verification_token(user_id, &verification_token)
            .await
            .map_err(|e| ApiError::from(DbError::from(e)))?;

        self.email_service.send_verification_email(&email, &verification_token)
            .await
            .map_err(|e| {
                error!("Failed to send verification email: {}", e);
                ApiError::new("Failed to send verification email", ApiErrorType::Internal)
            })?;

        info!("Successfully resent verification email to: {}", email);
        Ok(())
    }
}
/*
#[cfg(test)]
mod tests {
    // ... tests would need to be updated to provide TokenRevocationServiceTrait mock to UserService::new
}
*/
