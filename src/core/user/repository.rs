// src/core/user/repository.rs
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{Utc, Duration};
use super::model::{User, PasswordResetToken};
use crate::common::validation::UserInput;
use log::{error, info, debug};

pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        user_input: &UserInput,
        password_hash: String,
        verification_token: String,
    ) -> Result<User, sqlx::Error> {
        debug!("Creating new user with username: {}", user_input.username);

        let verification_token_expires_at = Utc::now() + Duration::hours(24);
        let now = Utc::now();

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (
                id,
                username,
                email,
                password_hash,
                is_email_verified,
                verification_token,
                verification_token_expires_at,
                created_at,
                updated_at,
                role
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
            Uuid::new_v4(),
            user_input.username,
            user_input.email,
            password_hash,
            false,
            Some(verification_token),
            Some(verification_token_expires_at),
            now,
            now,
            "user"  // Default role for new users
        )
            .fetch_one(&self.pool)
            .await;

        match &user {
            Ok(u) => info!("Successfully created user with id: {}", &u.id),
            Err(e) => error!("Failed to create user: {}", e),
        }

        user
    }

    pub async fn verify_email(&self, token: &str) -> Result<Option<Uuid>, sqlx::Error> {
        debug!("Attempting to verify email with token");

        let result = sqlx::query!(
            r#"
            UPDATE users
            SET is_email_verified = TRUE,
                verification_token = NULL,
                verification_token_expires_at = NULL,
                updated_at = $1
            WHERE verification_token = $2
              AND verification_token_expires_at > CURRENT_TIMESTAMP
            RETURNING id
            "#,
            Utc::now(),
            token
        )
            .fetch_optional(&self.pool)
            .await?;

        if let Some(ref r) = result {
            info!("Successfully verified email for user: {}", &r.id);
        } else {
            debug!("No user found with the provided verification token or token expired");
        }

        Ok(result.map(|r| r.id))
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, sqlx::Error> {
        debug!("Looking up user by id: {}", id);

        let user = sqlx::query_as!(
            User,
            r#"
            SELECT *
            FROM users
            WHERE id = $1
            "#,
            id
        )
            .fetch_optional(&self.pool)
            .await;

        if let Ok(Some(ref u)) = user {
            debug!("Found user: {}", &u.username);
        }

        user
    }

    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>, sqlx::Error> {
        debug!("Looking up user by username: {}", username);

        let user = sqlx::query_as!(
            User,
            r#"
            SELECT *
            FROM users
            WHERE username = $1
            "#,
            username
        )
            .fetch_optional(&self.pool)
            .await;

        if let Ok(Some(ref u)) = user {
            debug!("Found user: {}", &u.id);
        }

        user
    }

    pub async fn update(
        &self,
        id: Uuid,
        user_input: &UserInput,
        password_hash: Option<String>,
    ) -> Result<User, sqlx::Error> {
        debug!("Updating user: {}", id);

        let current_user = self.find_by_id(id)
            .await?
            .ok_or_else(|| {
                error!("User not found for update: {}", id);
                sqlx::Error::RowNotFound
            })?;

        let final_password_hash = password_hash.unwrap_or(current_user.password_hash);

        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET username = $1,
                email = $2,
                password_hash = $3,
                updated_at = $4
            WHERE id = $5
            RETURNING *
            "#,
            user_input.username,
            user_input.email,
            final_password_hash,
            Utc::now(),
            id
        )
            .fetch_one(&self.pool)
            .await;

        if let Ok(ref u) = user {
            info!("Successfully updated user: {}", &u.id);
        } else if let Err(ref e) = user {
            error!("Failed to update user {}: {}", id, e);
        }

        user
    }

    pub async fn delete(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        debug!("Attempting to delete user: {}", id);

        let result = sqlx::query!(
            r#"
            DELETE FROM users
            WHERE id = $1
            "#,
            id
        )
            .execute(&self.pool)
            .await?;

        let deleted = result.rows_affected() > 0;

        if deleted {
            info!("Successfully deleted user: {}", id);
        } else {
            debug!("No user found to delete with id: {}", id);
        }

        Ok(deleted)
    }

    pub async fn check_email_verified(&self, username: &str) -> Result<bool, sqlx::Error> {
        debug!("Checking email verification status for user: {}", username);

        let result = sqlx::query!(
            r#"
            SELECT is_email_verified
            FROM users
            WHERE username = $1
            "#,
            username
        )
            .fetch_optional(&self.pool)
            .await?;

        Ok(result.map_or(false, |r| r.is_email_verified))
    }

    pub async fn update_verification_token(
        &self,
        user_id: Uuid,
        token: &str,
    ) -> Result<(), sqlx::Error> {
        debug!("Updating verification token for user: {}", user_id);

        let expires_at = Utc::now() + Duration::hours(24);

        sqlx::query!(
            r#"
            UPDATE users
            SET verification_token = $1,
                verification_token_expires_at = $2,
                updated_at = $3
            WHERE id = $4
            "#,
            token,
            expires_at,
            Utc::now(),
            user_id
        )
            .execute(&self.pool)
            .await?;

        info!("Successfully updated verification token for user: {}", user_id);
        Ok(())
    }

    pub async fn create_password_reset_token(&self, user_id: Uuid) -> Result<PasswordResetToken, sqlx::Error> {
        debug!("Creating password reset token for user: {}", user_id);

        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::hours(1); // 1 hour expiration
        let now = Utc::now();

        let reset_token = sqlx::query_as!(
            PasswordResetToken,
            r#"
            INSERT INTO password_reset_tokens (
                id, user_id, token, expires_at, is_used, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
            Uuid::new_v4(),
            user_id,
            token,
            expires_at,
            false,
            now,
            now
        )
        .fetch_one(&self.pool)
        .await;

        match &reset_token {
            Ok(_t) => info!("Created password reset token for user: {}", user_id),
            Err(e) => error!("Failed to create password reset token: {}", e),
        }

        reset_token
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error> {
        debug!("Looking up user by email: {}", email);

        let user = sqlx::query_as!(
            User,
            r#"
            SELECT *
            FROM users
            WHERE email = $1
            "#,
            Some(email)
        )
        .fetch_optional(&self.pool)
        .await;

        if let Ok(Some(ref u)) = user {
            debug!("Found user: {}", &u.id);
        }

        user
    }

    pub async fn verify_reset_token(&self, token: &str) -> Result<Option<PasswordResetToken>, sqlx::Error> {
        debug!("Verifying password reset token");

        let reset_token = sqlx::query_as!(
            PasswordResetToken,
            r#"
            SELECT *
            FROM password_reset_tokens
            WHERE token = $1
              AND expires_at > CURRENT_TIMESTAMP
              AND is_used = false
            "#,
            token
        )
        .fetch_optional(&self.pool)
        .await;

        if let Ok(Some(ref t)) = reset_token {
            debug!("Found valid reset token for user: {}", t.user_id);
        }

        reset_token
    }

    pub async fn mark_reset_token_used(&self, token: &str) -> Result<bool, sqlx::Error> {
        debug!("Marking reset token as used");

        let result = sqlx::query!(
            r#"
            UPDATE password_reset_tokens
            SET is_used = true,
                updated_at = $1
            WHERE token = $2
              AND expires_at > CURRENT_TIMESTAMP
              AND is_used = false
            "#,
            Utc::now(),
            token
        )
        .execute(&self.pool)
        .await?;

        let updated = result.rows_affected() > 0;
        if updated {
            info!("Successfully marked reset token as used");
        } else {
            debug!("No valid reset token found to mark as used");
        }

        Ok(updated)
    }

    pub async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), sqlx::Error> {
        debug!("Updating password for user: {}", user_id);

        sqlx::query!(
            r#"
            UPDATE users
            SET password_hash = $1,
                updated_at = $2
            WHERE id = $3
            "#,
            password_hash,
            Utc::now(),
            user_id
        )
        .execute(&self.pool)
        .await?;

        info!("Successfully updated password for user: {}", user_id);
        Ok(())
    }

    #[cfg(test)]
    pub async fn clear_all(&self) -> Result<(), sqlx::Error> {
        sqlx::query!("DELETE FROM password_reset_tokens").execute(&self.pool).await?;
        sqlx::query!("DELETE FROM users").execute(&self.pool).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::validation::UserInput;
    use std::time::Duration as StdDuration;

    async fn setup_test_db() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must be set");
        PgPool::connect(&database_url).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_and_find_user() {
        let pool = setup_test_db().await;
        let repo = UserRepository::new(pool);

        let user_input = UserInput {
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            password: Some("TestPass123!".to_string()),
        };

        let created_user = repo.create(
            &user_input,
            "hashed_password".to_string(),
            "verification_token".to_string(),
        ).await.unwrap();

        assert_eq!(created_user.username, "testuser");

        let found_user = repo.find_by_username("testuser").await.unwrap().unwrap();
        assert_eq!(found_user.id, created_user.id);
    }

    #[tokio::test]
    async fn test_verify_email() {
        let pool = setup_test_db().await;
        let repo = UserRepository::new(pool);

        let user_input = UserInput {
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            password: Some("TestPass123!".to_string()),
        };

        let verification_token = "test_token";
        let created_user = repo.create(
            &user_input,
            "hashed_password".to_string(),
            verification_token.to_string(),
        ).await.unwrap();

        let result = repo.verify_email(verification_token).await.unwrap();
        assert_eq!(result, Some(created_user.id));

        let verified_user = repo.find_by_id(created_user.id).await.unwrap().unwrap();
        assert!(verified_user.is_email_verified);
    }

    #[tokio::test]
    async fn test_password_reset_flow() {
        let pool = setup_test_db().await;
        let repo = UserRepository::new(pool);

        // Create test user
        let user_input = UserInput {
            username: "resetuser".to_string(),
            email: Some("reset@example.com".to_string()),
            password: Some("TestPass123!".to_string()),
        };

        let created_user = repo.create(
            &user_input,
            "hashed_password".to_string(),
            "verification_token".to_string(),
        ).await.unwrap();

        // Create reset token
        let reset_token = repo.create_password_reset_token(created_user.id).await.unwrap();
        assert!(!reset_token.is_used);
        
        // Verify token
        let verified_token = repo.verify_reset_token(&reset_token.token).await.unwrap().unwrap();
        assert_eq!(verified_token.id, reset_token.id);

        // Mark token as used
        let marked_used = repo.mark_reset_token_used(&reset_token.token).await.unwrap();
        assert!(marked_used);

        // Verify token can't be used again
        let reused_token = repo.verify_reset_token(&reset_token.token).await.unwrap();
        assert!(reused_token.is_none());

        // Update password
        repo.update_password(created_user.id, "new_hashed_password").await.unwrap();
        
        // Verify password was updated
        let updated_user = repo.find_by_id(created_user.id).await.unwrap().unwrap();
        assert_eq!(updated_user.password_hash, "new_hashed_password");
    }

    #[tokio::test]
    async fn test_expired_reset_token() {
        let pool = setup_test_db().await;
        let repo = UserRepository::new(pool);

        // Create test user
        let user_input = UserInput {
            username: "expireduser".to_string(),
            email: Some("expired@example.com".to_string()),
            password: Some("TestPass123!".to_string()),
        };

        let created_user = repo.create(
            &user_input,
            "hashed_password".to_string(),
            "verification_token".to_string(),
        ).await.unwrap();

        // Create reset token
        let reset_token = repo.create_password_reset_token(created_user.id).await.unwrap();
        
        // Wait for token to expire (we'll use a short duration for testing)
        tokio::time::sleep(StdDuration::from_secs(1)).await;
        
        // Try to verify expired token
        let expired_token = repo.verify_reset_token(&reset_token.token).await.unwrap();
        assert!(expired_token.is_none());
    }

    #[tokio::test]
    async fn test_update_user() {
        let pool = setup_test_db().await;
        let repo = UserRepository::new(pool);

        let user_input = UserInput {
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            password: Some("TestPass123!".to_string()),
        };

        let created_user = repo.create(
            &user_input,
            "hashed_password".to_string(),
            "verification_token".to_string(),
        ).await.unwrap();

        let updated_input = UserInput {
            username: "updated_user".to_string(),
            email: Some("updated@example.com".to_string()),
            password: None,
        };

        let updated_user = repo.update(
            created_user.id,
            &updated_input,
            None,
        ).await.unwrap();

        assert_eq!(updated_user.username, "updated_user");
        assert_eq!(updated_user.email, Some("updated@example.com".to_string()));
    }
}
