use derive_more::Display;
use std::error::Error;
use crate::common::error::{ApiError, ApiErrorType};

#[derive(Debug, Display)]
pub enum AuthErrorType {
    #[display("Invalid credentials")]
    InvalidCredentials,
    #[display("Token expired")]
    TokenExpired,
    #[display("Invalid token")]
    InvalidToken,
    #[display("Email not verified")]
    EmailNotVerified,
}

#[derive(Debug, Display)]
#[display("{message}")]
pub struct AuthError {
    pub error_type: AuthErrorType,
    pub message: String,
}

impl AuthError {
    pub fn new(error_type: AuthErrorType) -> Self {
        Self {
            message: error_type.to_string(),
            error_type,
        }
    }
}

impl Error for AuthError {}

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> ApiError {
        ApiError::new(
            error.message,
            ApiErrorType::Authentication,
        )
    }
}
