use sqlx::{PgPool, Error as SqlxError};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use mockall::automock;
use async_trait::async_trait; // For async trait methods
use log::{debug, error, info, warn};
use serde::{Serialize, Deserialize};
use crate::core::auth::jwt::TokenType;

/// Represents an active token in the database
#[derive(Debug, Serialize, Deserialize, Clone)] // Added Clone for potential use in mocks
pub struct ActiveToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub jti: String,
    pub token_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub device_info: Option<serde_json::Value>,
}

#[automock]
#[async_trait]
pub trait ActiveTokenServiceTrait: Send + Sync {
    async fn record_token(
        &self,
        user_id: Uuid,
        jti: &str,
        token_type: TokenType,
        expires_at: DateTime<Utc>,
        device_info: Option<serde_json::Value>,
    ) -> Result<(), SqlxError>;

    async fn remove_token(&self, jti: &str) -> Result<bool, SqlxError>;
    async fn get_active_token(&self, jti: &str) -> Result<ActiveToken, SqlxError>;
    async fn get_user_tokens(&self, user_id: Uuid) -> Result<Vec<ActiveToken>, SqlxError>;
    async fn remove_all_user_tokens(&self, user_id: Uuid) -> Result<u64, SqlxError>;
    async fn cleanup_expired_tokens(&self) -> Result<u64, SqlxError>;
}

/// Service for managing active tokens
pub struct ActiveTokenService {
    pool: PgPool,
}

impl ActiveTokenService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ActiveTokenServiceTrait for ActiveTokenService {
    /// Record a new active token
    async fn record_token( // Removed pub
        &self,
        user_id: Uuid,
        jti: &str,
        token_type: TokenType,
        expires_at: DateTime<Utc>,
        device_info: Option<serde_json::Value>,
    ) -> Result<(), SqlxError> {
        debug!("Recording active token for user {}: {}", user_id, jti);
        
        let token_type_str = match token_type {
            TokenType::Access => "access",
            TokenType::Refresh => "refresh",
        };

        sqlx::query!(
            r#"
            INSERT INTO active_tokens (id, user_id, jti, token_type, expires_at, created_at, device_info)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            Uuid::new_v4(),
            user_id,
            jti,
            token_type_str,
            expires_at,
            Utc::now(),
            device_info,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Remove a token from active tokens (when used or expired)
    async fn remove_token(&self, jti: &str) -> Result<bool, SqlxError> { // Removed pub
        debug!("Removing active token: {}", jti);
        
        let result = sqlx::query!(
            r#"
            DELETE FROM active_tokens
            WHERE jti = $1
            RETURNING id
            "#,
            jti
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.is_some())
    }

    /// Get an active token by JTI
    async fn get_active_token(&self, jti: &str) -> Result<ActiveToken, SqlxError> { // Removed pub
        debug!("Getting active token: {}", jti);
        
        let token = sqlx::query_as!(
            ActiveToken,
            r#"
            SELECT 
                id, 
                user_id, 
                jti, 
                token_type, 
                expires_at, 
                created_at, 
                device_info
            FROM active_tokens
            WHERE jti = $1
            "#,
            jti
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(token)
    }

    /// Get all active tokens for a user
    async fn get_user_tokens(&self, user_id: Uuid) -> Result<Vec<ActiveToken>, SqlxError> { // Removed pub
        debug!("Getting active tokens for user: {}", user_id);
        
        let tokens = sqlx::query_as!(
            ActiveToken,
            r#"
            SELECT 
                id, 
                user_id, 
                jti, 
                token_type, 
                expires_at, 
                created_at, 
                device_info
            FROM active_tokens
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(tokens)
    }

    /// Remove all active tokens for a user
    async fn remove_all_user_tokens(&self, user_id: Uuid) -> Result<u64, SqlxError> { // Removed pub
        info!("Removing all active tokens for user: {}", user_id);
        
        let result = sqlx::query!(
            r#"
            DELETE FROM active_tokens
            WHERE user_id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Clean up expired tokens
    async fn cleanup_expired_tokens(&self) -> Result<u64, SqlxError> { // Removed pub
        debug!("Cleaning up expired active tokens");
        
        let result = sqlx::query!(
            r#"
            DELETE FROM active_tokens
            WHERE expires_at < $1
            "#,
            Utc::now(),
        )
        .execute(&self.pool)
        .await?;

        info!("Cleaned up {} expired active tokens", result.rows_affected());
        
        Ok(result.rows_affected())
    }
}
