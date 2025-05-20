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
    use super::*;
    use sqlx::error::DatabaseError; // For creating a mock DatabaseError
    use std::boxed::Box;
    use actix_web::http::StatusCode; // Keep for test_db_error_into_api_error_conversion

    #[test]
    fn test_db_error_display() {
        assert_eq!(DbError::ConnectionError("Failed to connect".to_string()).to_string(), "Database connection error: Failed to connect");
        assert_eq!(DbError::QueryError("Syntax error".to_string()).to_string(), "Database query error: Syntax error");
        assert_eq!(DbError::NotFound.to_string(), "Record not found");
        assert_eq!(DbError::DuplicateRecord.to_string(), "Duplicate record");
    }

    // Mock a simple DatabaseError for testing unique violation
    #[derive(Debug)]
    struct MockSqlxDatabaseError {
        code: Option<String>,
        message: String,
    }

    impl std::error::Error for MockSqlxDatabaseError {}

    impl std::fmt::Display for MockSqlxDatabaseError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    impl DatabaseError for MockSqlxDatabaseError {
        fn message(&self) -> &str {
            &self.message
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            self.code.as_deref().map(std::borrow::Cow::from)
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn is_unique_violation(&self) -> bool {
            self.code.as_deref() == Some("23505") // Standard PostgreSQL unique violation code
        }

        // Add the missing 'kind' method
        fn kind(&self) -> sqlx::error::ErrorKind {
            // For a mock, we can return a generic kind or one based on the code/message if needed.
            // Here, returning a common one like 'Other' or a specific one if the test requires it.
            // If testing specific kinds, this mock might need to be more sophisticated.
            sqlx::error::ErrorKind::Other
        }
        // Add other methods if needed by SqlxError variants, otherwise default or panic.
    }


    #[test]
    fn test_from_sqlx_error_conversion() {
        // Test RowNotFound
        let sqlx_not_found = SqlxError::RowNotFound;
        let db_error_not_found: DbError = sqlx_not_found.into();
        assert!(matches!(db_error_not_found, DbError::NotFound));

        // Test Unique Violation
        let mock_unique_violation_db_err = MockSqlxDatabaseError {
            code: Some("23505".to_string()),
            message: "unique constraint violation".to_string(),
        };
        let sqlx_unique_violation = SqlxError::Database(Box::new(mock_unique_violation_db_err));
        let db_error_unique: DbError = sqlx_unique_violation.into();
        assert!(matches!(db_error_unique, DbError::DuplicateRecord));

        // Test Other Database Error (e.g., connection error simulated via Io)
        let sqlx_other_error = SqlxError::Io(std::io::Error::new(std::io::ErrorKind::Other, "some other db issue"));
        let db_error_other: DbError = sqlx_other_error.into();
        if let DbError::QueryError(msg) = db_error_other {
            assert!(msg.contains("some other db issue"));
        } else {
            panic!("Expected DbError::QueryError for other SqlxError types");
        }
    }

    #[test]
    fn test_db_error_into_api_error_conversion() { // Renamed from test_db_error_conversion
        let db_not_found = DbError::NotFound;
        let api_not_found: ApiError = db_not_found.into();
        assert_eq!(api_not_found.error_type, ApiErrorType::NotFound);
        assert_eq!(api_not_found.status_code, StatusCode::NOT_FOUND);
        assert_eq!(api_not_found.message, "Record not found");

        let db_duplicate = DbError::DuplicateRecord;
        let api_duplicate: ApiError = db_duplicate.into();
        assert_eq!(api_duplicate.error_type, ApiErrorType::Validation);
        assert_eq!(api_duplicate.status_code, StatusCode::BAD_REQUEST);
        assert_eq!(api_duplicate.message, "Duplicate record");

        let db_query_error = DbError::QueryError("Test query error".to_string());
        let api_query_error: ApiError = db_query_error.into();
        assert_eq!(api_query_error.error_type, ApiErrorType::Database);
        assert_eq!(api_query_error.status_code, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(api_query_error.message, "Database query error: Test query error");
        
        let db_conn_error = DbError::ConnectionError("Test conn error".to_string());
        let api_conn_error: ApiError = db_conn_error.into();
        assert_eq!(api_conn_error.error_type, ApiErrorType::Database);
        assert_eq!(api_conn_error.status_code, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(api_conn_error.message, "Database connection error: Test conn error");
    }

    // Ensure the Error trait is implemented (compilation check)
    fn _is_error<T: Error>() {}
    fn _test_db_error_is_error() {
        _is_error::<DbError>();
    }
}
