// src/common/error/db_error.rs
use derive_more::Display;
use sqlx::error::Error as SqlxError;
use std::error::Error;
use crate::common::error::{ApiError, ApiErrorType};

#[derive(Debug, Display)]
pub enum DbError {
    #[display("Database connection error: {}", _0)]
    ConnectionError(String),
    #[display("Database query error: {}", _0)]
    QueryError(String),
    #[display("Record not found")]
    NotFound,
    #[display("Duplicate record")]
    DuplicateRecord,
}

impl Error for DbError {}

impl From<SqlxError> for DbError {
    fn from(error: SqlxError) -> Self {
        match error {
            SqlxError::RowNotFound => DbError::NotFound,
            SqlxError::Database(ref e) if e.is_unique_violation() => DbError::DuplicateRecord,
            _ => DbError::QueryError(error.to_string()),
        }
    }
}

impl From<DbError> for ApiError {
    fn from(error: DbError) -> ApiError {
        match error {
            DbError::NotFound => ApiError::new(error.to_string(), ApiErrorType::NotFound),
            DbError::DuplicateRecord => ApiError::new(error.to_string(), ApiErrorType::Validation),
            _ => ApiError::new(error.to_string(), ApiErrorType::Database),
        }
    }
}

#[cfg(test)]
mod tests {
    use actix_web::http::StatusCode;
    use crate::common::AuthError;
    use crate::common::error::auth_error::AuthErrorType;
    use super::*;

    #[test]
    fn test_api_error_creation() {
        let error = ApiError::new("Test error", ApiErrorType::Validation);
        assert_eq!(error.status_code, StatusCode::BAD_REQUEST);
        assert_eq!(error.message, "Test error");
    }

    #[test]
    fn test_auth_error_conversion() {
        let auth_error = AuthError::new(AuthErrorType::InvalidCredentials);
        let api_error: ApiError = auth_error.into();
        assert_eq!(api_error.status_code, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_db_error_conversion() {
        let db_error = DbError::NotFound;
        let api_error: ApiError = db_error.into();
        assert_eq!(api_error.status_code, StatusCode::NOT_FOUND);
    }
}
