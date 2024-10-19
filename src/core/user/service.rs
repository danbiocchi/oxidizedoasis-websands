// src/core/user/service.rs
use std::sync::Arc;
use bcrypt::{hash, DEFAULT_COST};
use uuid::Uuid;
use chrono::Utc;
use log::{debug, error, info};

use crate::common::{
    error::{ApiError, ApiErrorType},
    utils::{generate_secure_token, add_hours},
    validation::{UserInput, validate_and_sanitize_user_input},
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

        let validated_input = validate_and_sanitize_user_input(input)?;

        // Validate and hash password
        let password_hash = match &validated_input.password {
            Some(password) => hash(password.as_bytes(), DEFAULT_COST)
                .map_err(|e| {
                    error!("Failed to hash password: {}", e);
                    ApiError::new("Failed to process password", ApiErrorType::Internal)
                })?,
            None => {
                debug!("Password not provided for new user");
                return Err(ApiError::new("Password is required", ApiErrorType::Validation));
            }
        };

        // Generate verification token
        let verification_token = generate_secure_token();

        // Create user in database
        let user = self.repository.create(
            &validated_input,
            password_hash,
            verification_token.clone()
        )
            .await
            .map_err(|e| {
                error!("Database error while creating user: {}", e);
                ApiError::from(e)
            })?;

        // Send verification email if email provided
        if let Some(email) = &user.email {
            debug!("Sending verification email to: {}", email);
            if let Err(e) = self.email_service.send_verification_email(email, &verification_token).await {
                error!("Failed to send verification email: {}", e);
                // We don't return an error here as the user was created successfully
                // Instead, we log the error and the user can request a new verification email
            }
        }

        info!("Successfully created user: {}", user.id);
        Ok((user, verification_token))
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
                Err(ApiError::from(e))
            }
        }
    }

    pub async fn get_user_by_id(&self, id: Uuid) -> Result<User, ApiError> {
        debug!("Looking up user by id: {}", id);

        self.repository.find_by_id(id)
            .await
            .map_err(ApiError::from)?
            .ok_or_else(|| {
                debug!("User not found: {}", id);
                ApiError::new("User not found", ApiErrorType::NotFound)
            })
    }

    pub async fn update_user(&self, id: Uuid, input: UserInput) -> Result<User, ApiError> {
        debug!("Updating user: {}", id);

        let validated_input = validate_and_sanitize_user_input(input)?;

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
                ApiError::from(e)
            })
    }

    pub async fn delete_user(&self, id: Uuid) -> Result<(), ApiError> {
        debug!("Attempting to delete user: {}", id);

        let deleted = self.repository.delete(id)
            .await
            .map_err(|e| {
                error!("Database error while deleting user {}: {}", id, e);
                ApiError::from(e)
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
                ApiError::from(e)
            })
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
            .map_err(ApiError::from)?;

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
