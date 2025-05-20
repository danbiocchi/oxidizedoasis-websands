use derive_more::Display;
use std::error::Error;
use crate::common::error::{ApiError, ApiErrorType};

#[derive(Debug, Display, PartialEq, Clone)] // Added Clone
pub enum AuthErrorType {
    #[display("Invalid credentials")]
    InvalidCredentials,
    #[display("Token expired")]
    TokenExpired,
    #[display("Invalid token")]
    InvalidToken,
    #[display("Email not verified")]
    EmailNotVerified,
    #[display("Internal server error during authentication")]
    InternalServerError,
    #[display("Failed to create token")]
    TokenCreationError,
    #[display("User already exists")] // Added
    UserAlreadyExists,
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

    // Added new_with_message constructor
    pub fn new_with_message(error_type: AuthErrorType, message: &str) -> Self {
        Self {
            message: message.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_error_new() {
        let error_type = AuthErrorType::InvalidCredentials;
        let auth_error = AuthError::new(error_type.clone());
        assert_eq!(auth_error.error_type, AuthErrorType::InvalidCredentials);
        assert_eq!(auth_error.message, "Invalid credentials");
        assert_eq!(auth_error.to_string(), "Invalid credentials");
    }

    #[test]
    fn test_auth_error_new_with_message() {
        let error_type = AuthErrorType::TokenExpired;
        let custom_message = "Your session token has definitely expired.";
        let auth_error = AuthError::new_with_message(error_type.clone(), custom_message);
        assert_eq!(auth_error.error_type, AuthErrorType::TokenExpired);
        assert_eq!(auth_error.message, custom_message);
        assert_eq!(auth_error.to_string(), custom_message);
    }

    #[test]
    fn test_auth_error_type_display() {
        assert_eq!(AuthErrorType::InvalidCredentials.to_string(), "Invalid credentials");
        assert_eq!(AuthErrorType::TokenExpired.to_string(), "Token expired");
        assert_eq!(AuthErrorType::InvalidToken.to_string(), "Invalid token");
        assert_eq!(AuthErrorType::EmailNotVerified.to_string(), "Email not verified");
        assert_eq!(AuthErrorType::InternalServerError.to_string(), "Internal server error during authentication");
        assert_eq!(AuthErrorType::TokenCreationError.to_string(), "Failed to create token");
        assert_eq!(AuthErrorType::UserAlreadyExists.to_string(), "User already exists");
    }

    #[test]
    fn test_auth_error_from_into_api_error() {
        let auth_error = AuthError::new_with_message(AuthErrorType::InvalidToken, "Custom invalid token message.");
        let api_error: ApiError = auth_error.into();

        assert_eq!(api_error.message, "Custom invalid token message.");
        assert_eq!(api_error.error_type, ApiErrorType::Authentication);
    }

    // Ensure the Error trait is implemented (compilation check)
    fn _is_error<T: Error>() {}
    fn _test_auth_error_is_error() {
        _is_error::<AuthError>();
    }
}
