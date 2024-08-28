use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Represents a user in the database
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub is_email_verified: bool,
    pub verification_token: Option<String>,
    pub verification_token_expires_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Represents the data required to create a new user
#[derive(Deserialize, Debug)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Represents the data required for user login
#[derive(Deserialize)]
pub struct LoginUser {
    pub username: String,
    pub password: String,
}

/// Represents the data that can be updated for a user
#[derive(Deserialize)]
pub struct UpdateUser {
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Represents the user data that is safe to send in API responses
#[derive(Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub is_email_verified: bool,
    pub created_at: Option<DateTime<Utc>>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            username: user.username,
            email: user.email,
            is_email_verified: user.is_email_verified,
            created_at: user.created_at,
        }
    }
}