// src/core/user/service.rs
use std::sync::Arc;
use bcrypt::{hash, DEFAULT_COST};
use uuid::Uuid;
use log::{debug, error, info};

use crate::common::{
    error::{ApiError, ApiErrorType, DbError},
    utils::generate_secure_token,
    validation::{UserInput, validate_and_sanitize_user_input, validate_password},
};
use crate::core::email::EmailServiceTrait;
use super::{User, UserRepository};

pub struct UserService {
    repository: UserRepository,
    email_service: Arc<dyn EmailServiceTrait>,
}

impl UserService {
    pub fn new(repository: UserRepository, email_service: Arc<dyn EmailServiceTrait>) -> Self {
        Self {
            repository,
            email_service,
        }
    }

    pub async fn create_user(&self, input: UserInput) -> Result<(User, String), ApiError> {
        debug!("Creating new user with username: {}", input.username);

        let validated_input = validate_and_sanitize_user_input(input)
            .map_err(|_| ApiError::new("Invalid input", ApiErrorType::Validation))?;

        // Validate and hash password
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

        // Generate verification token
        let verification_token = generate_secure_token();
        let token_for_email = verification_token.clone();  // First clone for email
        let token_for_return = verification_token.clone(); // Second clone for return value

        // Create user in database
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

        // Send verification email if email provided
        if let Some(email) = &user.email {
            debug!("Sending verification email to: {}", email);
            if let Err(e) = self.email_service.send_verification_email(email, &token_for_email).await {
                error!("Failed to send verification email: {}", e);
                // We don't return an error here as the user was created successfully
                // Instead, we log the error and the user can request a new verification email
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

        self.repository.update(id, &validated_input, password_hash)
            .await
            .map_err(|e| {
                error!("Failed to update user {}: {}", id, e);
                ApiError::from(DbError::from(e))  // Convert sqlx::Error -> DbError -> ApiError
            })
    }

    pub async fn delete_user(&self, id: Uuid) -> Result<(), ApiError> {
        debug!("Attempting to delete user: {}", id);

        let deleted = self.repository.delete(id)
            .await
            .map_err(|e| {
                error!("Database error while deleting user {}: {}", id, e);
                ApiError::from(DbError::from(e))  // Convert sqlx::Error -> DbError -> ApiError
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
                ApiError::from(DbError::from(e))  // Convert sqlx::Error -> DbError -> ApiError
            })
    }

    pub async fn request_password_reset(&self, email: &str) -> Result<(), ApiError> {
        debug!("Processing password reset request for email: {}", email);

        // Find user by email
        let user = match self.repository.find_user_by_email(email).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                debug!("No user found with email: {}", email);
                // Return success to prevent email enumeration
                return Ok(());
            },
            Err(e) => return Err(ApiError::from(DbError::from(e))),
        };

        // Verify email is verified
        if !user.is_email_verified {
            debug!("Attempted password reset for unverified email: {}", email);
            return Err(ApiError::new("Email not verified", ApiErrorType::Validation));
        }

        // Create password reset token
        let reset_token = self.repository.create_password_reset_token(user.id)
            .await
            .map_err(|e| {
                error!("Failed to create password reset token: {}", e);
                ApiError::from(DbError::from(e))
            })?;

        // Send password reset email
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

        // Validate new password
        validate_password(new_password)
            .map_err(|e| {
                debug!("Invalid new password: {}", e);
                ApiError::new(e.to_string(), ApiErrorType::Validation)
            })?;

        // Verify and get reset token
        let reset_token = self.repository.verify_reset_token(token)
            .await
            .map_err(|e| ApiError::from(DbError::from(e)))?
            .ok_or_else(|| {
                debug!("Invalid or expired reset token");
                ApiError::new("Invalid or expired reset token", ApiErrorType::Validation)
            })?;

        // Hash new password
        let password_hash = hash(new_password.as_bytes(), DEFAULT_COST)
            .map_err(|e| {
                error!("Failed to hash new password: {}", e);
                ApiError::new("Failed to process password", ApiErrorType::Internal)
            })?;

        // Update password
        self.repository.update_password(reset_token.user_id, &password_hash)
            .await
            .map_err(|e| {
                error!("Failed to update password: {}", e);
                ApiError::from(DbError::from(e))
            })?;

        // Mark token as used
        self.repository.mark_reset_token_used(token)
            .await
            .map_err(|e| {
                error!("Failed to mark reset token as used: {}", e);
                ApiError::from(DbError::from(e))
            })?;

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

        // Update verification token in database
        self.repository.update_verification_token(user_id, &verification_token)
            .await
            .map_err(|e| ApiError::from(DbError::from(e)))?;

        // Send new verification email
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
    use super::*;
    use crate::core::email::mock::MockEmailService;
    use std::time::Duration as StdDuration;

    async fn setup_test_service() -> (UserService, Arc<MockEmailService>) {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must be set");
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        let repository = UserRepository::new(pool);
        let email_service = Arc::new(MockEmailService::new());
        let service = UserService::new(repository, email_service.clone());
        (service, email_service)
    }

    #[tokio::test]
    async fn test_create_user_success() {
        let (service, email_service) = setup_test_service().await;

        let input = UserInput {
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            password: Some("TestPass123!".to_string()),
        };

        let result = service.create_user(input).await;
        assert!(result.is_ok());

        let (user, token) = result.unwrap();
        assert_eq!(user.username, "testuser");
        assert!(!user.is_email_verified);

        let sent_emails = email_service.get_sent_emails();
        assert_eq!(sent_emails.len(), 1);
    }

    #[tokio::test]
    async fn test_verify_email() {
        let (service, _) = setup_test_service().await;

        let input = UserInput {
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            password: Some("TestPass123!".to_string()),
        };

        let (_, token) = service.create_user(input).await.unwrap();
        let result = service.verify_email(&token).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_user() {
        let (service, _) = setup_test_service().await;

        // Create initial user
        let input = UserInput {
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            password: Some("TestPass123!".to_string()),
        };

        let (user, _) = service.create_user(input).await.unwrap();

        // Update user
        let update_input = UserInput {
            username: "updated_user".to_string(),
            email: Some("updated@example.com".to_string()),
            password: None,
        };

        let updated_user = service.update_user(user.id, update_input).await.unwrap();
        assert_eq!(updated_user.username, "updated_user");
        assert_eq!(updated_user.email, Some("updated@example.com".to_string()));
    }

    #[tokio::test]
    async fn test_password_reset_flow() {
        let (service, email_service) = setup_test_service().await;

        // Create test user
        let input = UserInput {
            username: "resetuser".to_string(),
            email: Some("reset@example.com".to_string()),
            password: Some("TestPass123!".to_string()),
        };

        let (user, verification_token) = service.create_user(input).await.unwrap();
        
        // Verify email first
        service.verify_email(&verification_token).await.unwrap();

        // Request password reset
        service.request_password_reset("reset@example.com").await.unwrap();

        // Verify email was sent
        let sent_emails = email_service.get_sent_emails();
        assert_eq!(sent_emails.len(), 2); // Verification + reset emails

        // Get reset token from repository directly
        let reset_token = service.repository.find_user_by_email("reset@example.com")
            .await.unwrap().unwrap();

        // Verify token is valid
        service.verify_reset_token(&reset_token.verification_token.unwrap()).await.unwrap();

        // Reset password
        service.reset_password(
            &reset_token.verification_token.unwrap(),
            "NewPass123!"
        ).await.unwrap();

        // Try to reuse token (should fail)
        let reuse_result = service.reset_password(
            &reset_token.verification_token.unwrap(),
            "AnotherPass123!"
        ).await;
        assert!(reuse_result.is_err());
    }

    #[tokio::test]
    async fn test_password_reset_validation() {
        let (service, _) = setup_test_service().await;

        // Create and verify user
        let input = UserInput {
            username: "validateuser".to_string(),
            email: Some("validate@example.com".to_string()),
            password: Some("TestPass123!".to_string()),
        };

        let (_, verification_token) = service.create_user(input).await.unwrap();
        service.verify_email(&verification_token).await.unwrap();

        // Test invalid email
        let invalid_email_result = service.request_password_reset("nonexistent@example.com").await;
        assert!(invalid_email_result.is_ok()); // Should succeed to prevent email enumeration

        // Test invalid token
        let invalid_token_result = service.verify_reset_token("invalid_token").await;
        assert!(invalid_token_result.is_err());

        // Test weak password
        let reset_token = service.repository.find_user_by_email("validate@example.com")
            .await.unwrap().unwrap();
        let weak_password_result = service.reset_password(
            &reset_token.verification_token.unwrap(),
            "weak"
        ).await;
        assert!(weak_password_result.is_err());
    }

    #[tokio::test]
    async fn test_delete_user() {
        let (service, _) = setup_test_service().await;

        let input = UserInput {
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            password: Some("TestPass123!".to_string()),
        };

        let (user, _) = service.create_user(input).await.unwrap();
        assert!(service.delete_user(user.id).await.is_ok());
        assert!(service.get_user_by_id(user.id).await.is_err());
    }
}
*/
