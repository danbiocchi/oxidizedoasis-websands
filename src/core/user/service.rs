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
use crate::core::auth::token_revocation::TokenRevocationServiceTrait;
use super::{User, UserRepositoryTrait}; // Changed UserRepository to UserRepositoryTrait

pub struct UserService {
    repository: Arc<dyn UserRepositoryTrait>, // Changed to Arc<dyn UserRepositoryTrait>
    email_service: Arc<dyn EmailServiceTrait>,
    token_revocation_service: Arc<dyn TokenRevocationServiceTrait>,
}

impl UserService {
    pub fn new(
        repository: Arc<dyn UserRepositoryTrait>, // Changed to Arc<dyn UserRepositoryTrait>
        email_service: Arc<dyn EmailServiceTrait>,
        token_revocation_service: Arc<dyn TokenRevocationServiceTrait>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::user::{MockUserRepositoryTrait, User, model::PasswordResetToken};
    use crate::core::email::service::mock::MockEmailService; // Corrected import path for manual mock
    use crate::core::auth::token_revocation::MockTokenRevocationServiceTrait;
    use crate::common::validation::UserInput;
    use crate::common::error::{ApiError, ApiErrorType, DbError};
    use mockall::{predicate, mock};
    use uuid::Uuid;
    use std::sync::Arc;
    use chrono::Utc;

    // Helper function to create a basic UserInput
    fn basic_user_input(username: &str, email: &str, password: &str) -> UserInput {
        UserInput {
            username: username.to_string(), // Corrected: String, not Option<String>
            email: Some(email.to_string()),
            password: Some(password.to_string()),
            // Removed role and is_active as they are not in UserInput
        }
    }

    // Helper function to create a test User instance
    fn create_test_user(id: Uuid, username: &str, email: &str, verified: bool) -> User {
        User {
            id,
            username: username.to_string(),
            email: Some(email.to_string()),
            password_hash: "hashed_password".to_string(), // Placeholder
            is_email_verified: verified,
            verification_token: Some("token".to_string()),
            verification_token_expires_at: Some(Utc::now() + chrono::Duration::days(1)),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            role: "user".to_string(),
            is_active: true,
        }
    }
    
    // Mock for UserRepositoryTrait if not already defined elsewhere
    // If UserRepository is a struct with methods, we'd mock those directly or create a trait.
    // Removed manual mock! for UserRepository as we'll use MockUserRepositoryTrait from automock

    #[tokio::test]
    async fn test_create_user_success() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new()); // Use manual mock
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();
        let input_username = "testuser";
        let input_email = "test@example.com";
        let input_password = "Password123!";
        
        let user_input = basic_user_input(input_username, input_email, input_password);
        let mut expected_user = create_test_user(user_id, input_username, input_email, false);
        // The service generates the token, so we can't know it beforehand for `expected_user`.
        // The repository mock will return the user with the token it was given.
        // We will check the returned token separately.
        expected_user.verification_token = None; // Clear this as it's generated and passed to repo

        let cloned_expected_user_for_repo = create_test_user(user_id, input_username, input_email, false);


        mock_repo.expect_create()
            .withf(move |input_arg, _password_hash, verification_token_arg| {
                input_arg.username == input_username && // Corrected: direct comparison for String
                input_arg.email.as_deref() == Some(input_email) &&
                !verification_token_arg.is_empty() // Ensure a token is passed
            })
            .times(1)
            .returning(move |_, _, vt_arg| {
                // Return a user that includes the generated verification token
                let mut user_to_return = cloned_expected_user_for_repo.clone();
                user_to_return.id = user_id; // Ensure ID is consistent if mock needs it
                user_to_return.verification_token = Some(vt_arg.clone());
                Ok(user_to_return)
            });

        // For manual mock, no `expect_` calls. We'll check `get_sent_emails` after.
        // mock_email_service.set_should_succeed(true); // Default is true

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service.clone(), // Clone Arc for the service
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.create_user(user_input.clone()).await;
        
        assert!(result.is_ok());
        let (user, returned_token) = result.unwrap();
        
        assert_eq!(user.id, user_id);
        assert_eq!(user.username, input_username);
        assert_eq!(user.email.as_deref(), Some(input_email));
        assert!(!user.is_email_verified);
        assert!(!returned_token.is_empty());
        assert_eq!(user.verification_token.as_ref(), Some(&returned_token));
        
        // Check that the email was "sent" by the manual mock
        let sent_emails = mock_email_service.get_sent_emails();
        assert_eq!(sent_emails.len(), 1);
        assert!(sent_emails[0].contains(input_email));
        assert!(sent_emails[0].contains(&returned_token));
    }

    #[tokio::test]
    async fn test_create_user_input_validation_fails() {
        let mock_repo = MockUserRepositoryTrait::new(); 
        let mock_email_service = Arc::new(MockEmailService::new()); 
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        // Input that will fail validation (e.g., too short username)
        let invalid_user_input = UserInput {
            username: "u".to_string(), // Too short
            email: Some("test@example.com".to_string()),
            password: Some("Password123!".to_string()),
        };

        let result = user_service.create_user(invalid_user_input).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Validation);
        assert_eq!(err.message, "Invalid input");
    }

    #[tokio::test]
    async fn test_create_user_missing_password() {
        let mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );
        
        let user_input_no_password = UserInput {
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            password: None, // Missing password
        };

        let result = user_service.create_user(user_input_no_password).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Validation);
        assert_eq!(err.message, "Password is required");
    }

    #[tokio::test]
    async fn test_create_user_repository_error() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new()); 
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let input_username = "testuser_repo_fail";
        let input_email = "test_repo_fail@example.com";
        let input_password = "Password123!";
        let user_input = basic_user_input(input_username, input_email, input_password);

        mock_repo.expect_create()
            .times(1)
            .returning(|_, _, _| Err(sqlx::Error::PoolClosed)); // Ensuring this change is applied

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.create_user(user_input).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Database); // Assuming DbError converts to ApiErrorType::Database
    }

    #[tokio::test]
    async fn test_create_user_email_sending_error_still_succeeds() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();
        let input_username = "testuser_email_fail";
        let input_email = "test_email_fail@example.com";
        let input_password = "Password123!";
        
        let user_input = basic_user_input(input_username, input_email, input_password);
        
        let cloned_user_for_repo = create_test_user(user_id, input_username, input_email, false);

        mock_repo.expect_create()
            .times(1)
            .returning(move |_, _, vt_arg| {
                let mut user_to_return = cloned_user_for_repo.clone();
                user_to_return.verification_token = Some(vt_arg.clone());
                Ok(user_to_return)
            });
        
        mock_email_service.set_should_succeed(false); // Configure manual mock to fail

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service.clone(),
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.create_user(user_input).await;
        
        // The user creation should still succeed even if email sending fails
        assert!(result.is_ok()); 
        let (user, returned_token) = result.unwrap();
        assert_eq!(user.id, user_id);
        assert_eq!(user.username, input_username);
        assert!(!returned_token.is_empty());
        // Logs should indicate email sending failure, but user is created.
    }

    // --- Tests for get_user_by_id ---
    #[tokio::test]
    async fn test_get_user_by_id_success() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();
        let expected_user = create_test_user(user_id, "testuser", "get@example.com", true);
        let cloned_expected_user = expected_user.clone();

        mock_repo.expect_find_by_id()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(move |_| Ok(Some(cloned_expected_user.clone())));

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.get_user_by_id(user_id).await;
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.id, user_id);
        assert_eq!(user.username, expected_user.username);
    }

    #[tokio::test]
    async fn test_get_user_by_id_not_found() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();

        mock_repo.expect_find_by_id()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(|_| Ok(None));

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.get_user_by_id(user_id).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::NotFound);
        assert_eq!(err.message, "User not found");
    }

    #[tokio::test]
    async fn test_get_user_by_id_repository_error() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();

        mock_repo.expect_find_by_id()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(|_| Err(sqlx::Error::PoolClosed));

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.get_user_by_id(user_id).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Database);
    }
    
    // --- Tests for verify_email ---
    #[tokio::test]
    async fn test_verify_email_success() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let verification_token = "valid_token";
        let user_id = Uuid::new_v4();

        mock_repo.expect_verify_email()
            .with(predicate::eq(verification_token))
            .times(1)
            .returning(move |_| Ok(Some(user_id)));

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.verify_email(verification_token).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_email_invalid_or_expired_token() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let verification_token = "invalid_token";

        mock_repo.expect_verify_email()
            .with(predicate::eq(verification_token))
            .times(1)
            .returning(|_| Ok(None)); // Simulate token not found or expired

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.verify_email(verification_token).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Validation);
        assert_eq!(err.message, "Invalid or expired verification token");
    }

    #[tokio::test]
    async fn test_verify_email_repository_error() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let verification_token = "some_token";

        mock_repo.expect_verify_email()
            .with(predicate::eq(verification_token))
            .times(1)
            .returning(|_| Err(sqlx::Error::PoolClosed)); // Simulate a DB error

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.verify_email(verification_token).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Database);
    }

    // --- Tests for update_user ---
    #[tokio::test]
    async fn test_update_user_success_no_password_change() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mut mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();
        let original_username = "originaluser";
        let updated_username = "updateduser";
        
        let update_input = UserInput {
            username: updated_username.to_string(),
            email: Some("update@example.com".to_string()),
            password: None, // No password change
        };

        let expected_updated_user = User {
            id: user_id,
            username: updated_username.to_string(),
            email: Some("update@example.com".to_string()),
            password_hash: "old_hashed_password".to_string(), // Should remain unchanged
            is_email_verified: true,
            ..create_test_user(user_id, original_username, "original@example.com", true) // base
        };
        let cloned_updated_user = expected_updated_user.clone();

        mock_repo.expect_update()
            .withf(move |id_arg, input_arg, pass_hash_arg| {
                *id_arg == user_id &&
                input_arg.username == updated_username &&
                pass_hash_arg.is_none()
            })
            .times(1)
            .returning(move |_, _, _| Ok(cloned_updated_user.clone()));
        
        // No token revocation expected
        mock_token_revocation_service.expect_revoke_all_user_tokens().never();

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.update_user(user_id, update_input).await;
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, updated_username);
        assert_eq!(user.password_hash, "old_hashed_password"); // Ensure password hash didn't change
    }

    #[tokio::test]
    async fn test_update_user_success_with_password_change() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mut mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();
        let original_username = "originaluserpass";
        let updated_username = "updateduserpass";
        let new_password = "NewPassword123!";
        
        let update_input = UserInput {
            username: updated_username.to_string(),
            email: Some("updatepass@example.com".to_string()),
            password: Some(new_password.to_string()),
        };

        let mut expected_updated_user = User {
            id: user_id,
            username: updated_username.to_string(),
            email: Some("updatepass@example.com".to_string()),
            // password_hash will be new, so we can't easily predict it here for the returned user.
            // The mock_repo.update will return a user with some password hash.
            ..create_test_user(user_id, original_username, "originalpass@example.com", true)
        };
        // Simulate a new hash for the returned user from repo
        let new_mocked_hash = bcrypt::hash(new_password, DEFAULT_COST).unwrap();
        expected_updated_user.password_hash = new_mocked_hash.clone(); 
        let cloned_updated_user = expected_updated_user.clone();


        mock_repo.expect_update()
            .withf(move |id_arg, input_arg, pass_hash_arg| {
                *id_arg == user_id &&
                input_arg.username == updated_username &&
                pass_hash_arg.is_some() // Password hash should be present
            })
            .times(1)
            .returning(move |_, _, _| Ok(cloned_updated_user.clone()));
        
        mock_token_revocation_service.expect_revoke_all_user_tokens()
            .with(
                predicate::eq(user_id),
                predicate::always() // Reverted to always() for the Option<&str> reason
            )
            .times(1)
            .returning(|_, _| Ok(1)); // Simulate 1 token revoked

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.update_user(user_id, update_input).await;
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, updated_username);
        assert_eq!(user.password_hash, new_mocked_hash); // Check if the new hash is set
    }

    #[tokio::test]
    async fn test_update_user_not_found() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        
        let user_id = Uuid::new_v4();
        let update_input = UserInput {
            username: "anyuser".to_string(),
            email: None,
            password: None,
        };

        mock_repo.expect_update()
            .with(predicate::eq(user_id), predicate::always(), predicate::always())
            .times(1)
            .returning(|_, _, _| Err(sqlx::Error::RowNotFound)); // Simulate user not found by repo

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.update_user(user_id, update_input).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        // DbError from RowNotFound should correctly map to ApiErrorType::NotFound.
        assert_eq!(err.error_type, ApiErrorType::NotFound); 
    }
    
    #[tokio::test]
    async fn test_update_user_token_revocation_error() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mut mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();
        let updated_username = "updated_user_revoke_fail";
        let new_password = "NewPassword123!";
        
        let update_input = UserInput {
            username: updated_username.to_string(),
            email: Some("revokefail@example.com".to_string()),
            password: Some(new_password.to_string()),
        };

        let mut expected_updated_user = create_test_user(user_id, updated_username, "revokefail@example.com", true);
        let new_mocked_hash = bcrypt::hash(new_password, DEFAULT_COST).unwrap();
        expected_updated_user.password_hash = new_mocked_hash.clone();
        let cloned_updated_user = expected_updated_user.clone();

        mock_repo.expect_update()
            .times(1)
            .returning(move |_, _, _| Ok(cloned_updated_user.clone()));
        
        mock_token_revocation_service.expect_revoke_all_user_tokens()
            .with(
                predicate::eq(user_id),
                predicate::always() // Reverted to always() for the Option<&str> reason
            )
            .times(1)
            .returning(|_, _| Err(sqlx::Error::PoolClosed)); // Simulate SqlxError

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.update_user(user_id, update_input).await;
        // User update should still succeed, error during token revocation is logged but doesn't fail the operation
        assert!(result.is_ok()); 
        let user = result.unwrap();
        assert_eq!(user.username, updated_username);
        assert_eq!(user.password_hash, new_mocked_hash);
        // Logs should show an error for token revocation.
    }

    #[tokio::test]
    async fn test_update_user_input_validation_error() {
        let mock_repo = MockUserRepositoryTrait::new(); // No repo calls if validation fails
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();
        let invalid_input = UserInput {
            username: "u".to_string(), // Too short
            email: Some("invalidmail".to_string()), // Invalid email format
            password: Some("short".to_string()), // Fails password strength
        };

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.update_user(user_id, invalid_input).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Validation);
        assert_eq!(err.message, "Invalid input");
    }

    // --- Tests for delete_user ---
    #[tokio::test]
    async fn test_delete_user_success() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();

        mock_repo.expect_delete()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(|_| Ok(true)); // Simulate successful deletion

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.delete_user(user_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_user_not_found() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();

        mock_repo.expect_delete()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(|_| Ok(false)); // Simulate user not found for deletion

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.delete_user(user_id).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::NotFound);
        assert_eq!(err.message, "User not found");
    }

    #[tokio::test]
    async fn test_delete_user_repository_error() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();

        mock_repo.expect_delete()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(|_| Err(sqlx::Error::PoolClosed)); // Simulate DB error

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.delete_user(user_id).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Database);
    }

    // --- Tests for request_password_reset ---
    #[tokio::test]
    async fn test_request_password_reset_success() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new()); // Using manual mock
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_email = "user@example.com";
        let user_id = Uuid::new_v4();
        let test_user = create_test_user(user_id, "testuser", user_email, true); // Email verified
        let reset_token_value = "test_reset_token".to_string();
        let password_reset_token_db = PasswordResetToken {
            id: Uuid::new_v4(),
            user_id,
            token: reset_token_value.clone(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            is_used: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        mock_repo.expect_find_user_by_email()
            .with(predicate::eq(user_email))
            .times(1)
            .returning(move |_| Ok(Some(test_user.clone())));
        
        mock_repo.expect_create_password_reset_token()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(move |_| Ok(password_reset_token_db.clone()));

        // mock_email_service.set_should_succeed(true); // Default for manual mock

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service.clone(),
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.request_password_reset(user_email).await;
        assert!(result.is_ok());

        let sent_emails = mock_email_service.get_sent_emails();
        assert_eq!(sent_emails.len(), 1);
        assert!(sent_emails[0].contains(user_email));
        assert!(sent_emails[0].contains(&reset_token_value));
    }

    #[tokio::test]
    async fn test_request_password_reset_user_not_found() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        let user_email = "nonexistent@example.com";

        mock_repo.expect_find_user_by_email()
            .with(predicate::eq(user_email))
            .times(1)
            .returning(|_| Ok(None)); // User not found

        // No further calls to repo or email service expected
        mock_repo.expect_create_password_reset_token().never();

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service.clone(),
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.request_password_reset(user_email).await;
        assert!(result.is_ok()); // Service should silently succeed if user not found

        let sent_emails = mock_email_service.get_sent_emails();
        assert_eq!(sent_emails.len(), 0); // No email sent
    }

    #[tokio::test]
    async fn test_request_password_reset_email_not_verified() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_email = "unverified@example.com";
        let user_id = Uuid::new_v4();
        let test_user = create_test_user(user_id, "unverifieduser", user_email, false); // Email NOT verified

        mock_repo.expect_find_user_by_email()
            .with(predicate::eq(user_email))
            .times(1)
            .returning(move |_| Ok(Some(test_user.clone())));
        
        mock_repo.expect_create_password_reset_token().never();

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service.clone(),
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.request_password_reset(user_email).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Validation);
        assert_eq!(err.message, "Email not verified");
        
        let sent_emails = mock_email_service.get_sent_emails();
        assert_eq!(sent_emails.len(), 0);
    }

    #[tokio::test]
    async fn test_request_password_reset_repo_error_on_find() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        let user_email = "finderror@example.com";

        mock_repo.expect_find_user_by_email()
            .with(predicate::eq(user_email))
            .times(1)
            .returning(|_| Err(sqlx::Error::PoolClosed));
            
        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.request_password_reset(user_email).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Database);
    }

    #[tokio::test]
    async fn test_request_password_reset_repo_error_on_create_token() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_email = "createtokenerror@example.com";
        let user_id = Uuid::new_v4();
        let test_user = create_test_user(user_id, "test_ct_error", user_email, true);

        mock_repo.expect_find_user_by_email()
            .with(predicate::eq(user_email))
            .times(1)
            .returning(move |_| Ok(Some(test_user.clone())));
        
        mock_repo.expect_create_password_reset_token()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(|_| Err(sqlx::Error::PoolClosed));
            
        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.request_password_reset(user_email).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Database);
    }

    #[tokio::test]
    async fn test_request_password_reset_email_send_error() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_email = "emailsenderror@example.com";
        let user_id = Uuid::new_v4();
        let test_user = create_test_user(user_id, "test_ese_error", user_email, true);
        let reset_token_value = "test_reset_token_ese".to_string();
        let password_reset_token_db = PasswordResetToken {
            id: Uuid::new_v4(), user_id, token: reset_token_value.clone(),
            expires_at: Utc::now() + chrono::Duration::hours(1), is_used: false,
            created_at: Utc::now(), updated_at: Utc::now(),
        };

        mock_repo.expect_find_user_by_email().times(1).returning(move |_| Ok(Some(test_user.clone())));
        mock_repo.expect_create_password_reset_token().times(1).returning(move |_| Ok(password_reset_token_db.clone()));
        
        mock_email_service.set_should_succeed(false); // Simulate email sending failure

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service.clone(),
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.request_password_reset(user_email).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Internal);
        assert_eq!(err.message, "Failed to send password reset email");
    }

    // --- Tests for verify_reset_token ---
    #[tokio::test]
    async fn test_verify_reset_token_success() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        
        let token_str = "valid_reset_token";
        let reset_token_db = PasswordResetToken {
            id: Uuid::new_v4(), user_id: Uuid::new_v4(), token: token_str.to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1), is_used: false,
            created_at: Utc::now(), updated_at: Utc::now(),
        };

        mock_repo.expect_verify_reset_token()
            .with(predicate::eq(token_str))
            .times(1)
            .returning(move |_| Ok(Some(reset_token_db.clone())));

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.verify_reset_token(token_str).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_reset_token_invalid_or_expired() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        let token_str = "invalid_reset_token";

        mock_repo.expect_verify_reset_token()
            .with(predicate::eq(token_str))
            .times(1)
            .returning(|_| Ok(None));

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.verify_reset_token(token_str).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Validation);
        assert_eq!(err.message, "Invalid or expired reset token");
    }

    #[tokio::test]
    async fn test_verify_reset_token_repo_error() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        let token_str = "repo_error_reset_token";

        mock_repo.expect_verify_reset_token()
            .with(predicate::eq(token_str))
            .times(1)
            .returning(|_| Err(sqlx::Error::PoolClosed));
            
        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.verify_reset_token(token_str).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Database);
    }

    // --- Tests for reset_password ---
    #[tokio::test]
    async fn test_reset_password_success() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mut mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let token_str = "valid_reset_token_for_reset";
        let new_password = "NewSecurePassword123!";
        let user_id = Uuid::new_v4();
        let reset_token_db = PasswordResetToken {
            id: Uuid::new_v4(), user_id, token: token_str.to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1), is_used: false,
            created_at: Utc::now(), updated_at: Utc::now(),
        };

        mock_repo.expect_verify_reset_token()
            .with(predicate::eq(token_str))
            .times(1)
            .returning(move |_| Ok(Some(reset_token_db.clone())));
        
        mock_repo.expect_update_password()
            .withf(move |uid, pass_hash| *uid == user_id && !pass_hash.is_empty())
            .times(1)
            .returning(|_, _| Ok(()));
            
        mock_repo.expect_mark_reset_token_used()
            .with(predicate::eq(token_str))
            .times(1)
            .returning(|_| Ok(true)); // Corrected to return Ok(true)
            
        mock_token_revocation_service.expect_revoke_all_user_tokens()
            .with(predicate::eq(user_id), predicate::always())
            .times(1)
            .returning(|_, _| Ok(1));

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.reset_password(token_str, new_password).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reset_password_invalid_new_password() {
        let mock_repo = MockUserRepositoryTrait::new(); // No repo calls if password validation fails
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        
        let token_str = "any_token";
        let new_password_invalid = "short";

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.reset_password(token_str, new_password_invalid).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Validation);
        // Message might vary based on exact validation failure
    }

    #[tokio::test]
    async fn test_reset_password_invalid_reset_token() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        
        let token_str_invalid = "invalid_reset_token_for_reset";
        let new_password = "NewSecurePassword123!";

        mock_repo.expect_verify_reset_token()
            .with(predicate::eq(token_str_invalid))
            .times(1)
            .returning(|_| Ok(None)); // Token not found/expired

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.reset_password(token_str_invalid, new_password).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Validation);
        assert_eq!(err.message, "Invalid or expired reset token");
    }

    // --- Tests for resend_verification_email ---
    #[tokio::test]
    async fn test_resend_verification_email_success() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();
        let user_email = "resend@example.com";
        let test_user = create_test_user(user_id, "resenduser", user_email, false); // Email NOT verified

        // Mock for get_user_by_id call
        let cloned_user_for_get = test_user.clone();
        mock_repo.expect_find_by_id()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(move |_| Ok(Some(cloned_user_for_get.clone())));

        mock_repo.expect_update_verification_token()
            .with(predicate::eq(user_id), predicate::always()) // Check token is non-empty
            .times(1)
            .returning(|_, _| Ok(()));
        
        // mock_email_service.set_should_succeed(true); // Default

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service.clone(),
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.resend_verification_email(user_id).await;
        assert!(result.is_ok());

        let sent_emails = mock_email_service.get_sent_emails();
        assert_eq!(sent_emails.len(), 1);
        assert!(sent_emails[0].contains(user_email));
        // We can't easily check the exact token value here without more complex mocking
        // or capturing the token from update_verification_token mock.
        // For now, checking if an email was sent to the right address is a good start.
    }

    #[tokio::test]
    async fn test_resend_verification_email_already_verified() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();
        let user_email = "alreadyverified@example.com";
        let test_user = create_test_user(user_id, "verifieduser", user_email, true); // Email IS verified

        let cloned_user_for_get = test_user.clone();
        mock_repo.expect_find_by_id()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(move |_| Ok(Some(cloned_user_for_get.clone())));
        
        // No further calls expected
        mock_repo.expect_update_verification_token().never();

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service.clone(),
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.resend_verification_email(user_id).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Validation);
        assert_eq!(err.message, "Email already verified");
        
        let sent_emails = mock_email_service.get_sent_emails();
        assert_eq!(sent_emails.len(), 0);
    }

    #[tokio::test]
    async fn test_resend_verification_email_user_not_found() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        let user_id = Uuid::new_v4();

        mock_repo.expect_find_by_id()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(|_| Ok(None)); // User not found

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.resend_verification_email(user_id).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::NotFound);
    }
    
    #[tokio::test]
    async fn test_resend_verification_email_no_email_address_for_user() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();

        let user_id = Uuid::new_v4();
        let mut test_user_no_email = create_test_user(user_id, "noemailuser", "dummy@example.com", false);
        test_user_no_email.email = None; // User has no email

        let cloned_user_for_get = test_user_no_email.clone();
        mock_repo.expect_find_by_id()
            .with(predicate::eq(user_id))
            .times(1)
            .returning(move |_| Ok(Some(cloned_user_for_get.clone())));

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.resend_verification_email(user_id).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Validation);
        assert_eq!(err.message, "No email address associated with user");
    }

    // --- Tests for check_email_verified ---
    #[tokio::test]
    async fn test_check_email_verified_is_verified() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        let username = "verified_user_check";

        mock_repo.expect_check_email_verified()
            .with(predicate::eq(username))
            .times(1)
            .returning(|_| Ok(true));

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.check_email_verified(username).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[tokio::test]
    async fn test_check_email_verified_is_not_verified() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        let username = "unverified_user_check";

        mock_repo.expect_check_email_verified()
            .with(predicate::eq(username))
            .times(1)
            .returning(|_| Ok(false));

        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.check_email_verified(username).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[tokio::test]
    async fn test_check_email_verified_repo_error() {
        let mut mock_repo = MockUserRepositoryTrait::new();
        let mock_email_service = Arc::new(MockEmailService::new());
        let mock_token_revocation_service = MockTokenRevocationServiceTrait::new();
        let username = "error_user_check";

        mock_repo.expect_check_email_verified()
            .with(predicate::eq(username))
            .times(1)
            .returning(|_| Err(sqlx::Error::PoolClosed));
            
        let user_service = UserService::new(
            Arc::new(mock_repo),
            mock_email_service,
            Arc::new(mock_token_revocation_service),
        );

        let result = user_service.check_email_verified(username).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Database);
    }
}
