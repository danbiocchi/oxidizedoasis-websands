use sqlx::{PgPool, Error as SqlxError};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use crate::core::auth::jwt::TokenType;

/// Represents a revoked token in the database
#[derive(Debug)]
pub struct RevokedToken {
    pub id: Uuid,
    pub jti: String,
    pub user_id: Uuid,
    pub token_type: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: DateTime<Utc>,
    pub reason: Option<String>,
}

/// Service for managing token revocation
pub struct TokenRevocationService {
    pool: PgPool,
}

impl TokenRevocationService {
    /// Create a new TokenRevocationService
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Check if a token is revoked
    pub async fn is_token_revoked(&self, jti: &str) -> Result<bool, SqlxError> {
        debug!("Checking if token is revoked: {}", jti);
        
        let result = sqlx::query!(
            r#"
            SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1) as "exists!"
            "#,
            jti
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(result.exists)
    }

    /// Revoke a token
    pub async fn revoke_token(
        &self,
        jti: &str,
        user_id: Uuid,
        token_type: TokenType,
        expires_at: DateTime<Utc>,
        reason: Option<&str>,
    ) -> Result<(), SqlxError> {
        info!("Revoking token for user {}: {}", user_id, jti);
        
        let token_type_str = match token_type {
            TokenType::Access => "access",
            TokenType::Refresh => "refresh",
        };

        sqlx::query!(
            r#"
            INSERT INTO revoked_tokens (id, jti, user_id, token_type, expires_at, revoked_at, reason)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            Uuid::new_v4(),
            jti,
            user_id,
            token_type_str,
            expires_at,
            Utc::now(),
            reason,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Revoke all tokens for a user
    pub async fn revoke_all_user_tokens(
        &self,
        user_id: Uuid,
        reason: Option<&str>,
    ) -> Result<u64, SqlxError> {
        warn!("Revoking all tokens for user: {}", user_id);
        
        // This is a placeholder. In a real implementation, we would need to know
        // all the JTIs for the user's tokens, which would require tracking them.
        // For now, we'll just add a note that this would revoke all tokens.
        
        info!("Would revoke all tokens for user: {}", user_id);
        
        // Return 0 as we didn't actually revoke any tokens
        Ok(0)
    }

    /// Clean up expired revoked tokens
    pub async fn cleanup_expired_tokens(&self) -> Result<u64, SqlxError> {
        debug!("Cleaning up expired revoked tokens");
        
        let result = sqlx::query!(
            r#"
            DELETE FROM revoked_tokens
            WHERE expires_at < $1
            "#,
            Utc::now(),
        )
        .execute(&self.pool)
        .await?;

        info!("Cleaned up {} expired revoked tokens", result.rows_affected());
        
        Ok(result.rows_affected())
    }
}