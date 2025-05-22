use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)] // Added Clone
pub struct PasswordResetToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub is_used: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordResetVerify {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordResetSubmit {
    pub token: String,
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)] // Added Clone
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub is_email_verified: bool,
    pub verification_token: Option<String>,
    pub verification_token_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub role: String,
    pub is_active: bool,
}

// Struct for updating an existing user
#[derive(Debug, Deserialize, Serialize, Clone, Default)] // Added Default for easier test setup
pub struct UserUpdate {
    pub username: Option<String>,
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub is_email_verified: Option<bool>,
    pub verification_token: Option<Option<String>>, // Use Option<Option<String>> to allow setting to Some(None) to clear the token
    pub verification_token_expires_at: Option<Option<DateTime<Utc>>>, // Use Option<Option<DateTime<Utc>>> to allow setting to Some(None) to clear the expiration
    pub role: Option<String>,
    pub is_active: Option<bool>,
}


// Struct for creating a new user
#[derive(Debug, Deserialize, Serialize, Clone)] // Added Clone, Serialize, Deserialize for flexibility
pub struct NewUser {
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub is_email_verified: bool,
    pub role: String,
    pub verification_token: Option<String>,
    pub verification_token_expires_at: Option<DateTime<Utc>>,
    // is_active is typically true by default, can be omitted or set by repository
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub is_email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub role: String,
    pub is_active: bool,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            username: user.username,
            email: user.email,
            is_email_verified: user.is_email_verified,
            created_at: user.created_at,
            role: user.role,
            is_active: user.is_active,
        }
    }
}
