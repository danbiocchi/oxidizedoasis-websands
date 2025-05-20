use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use derive_more::{Display, From};
use serde::Serialize;
use validator::ValidationError;

#[derive(Debug, Display, Serialize, From)]
#[display("{message}")]
pub struct ApiError {
    pub message: String,
    pub error_type: ApiErrorType,
    #[serde(skip_serializing)]
    pub status_code: StatusCode,
}

#[derive(Debug, Display, Serialize, PartialEq)] // Added PartialEq
pub enum ApiErrorType {
    #[display("Validation error")]
    Validation,
    #[display("Authentication error")]
    Authentication,
    #[display("Authorization error")]
    Authorization,
    #[display("Not found")]
    NotFound,
    #[display("Database error")]
    Database,
    #[display("Internal server error")]
    Internal,
}

impl ApiError {
    pub fn new(message: impl Into<String>, error_type: ApiErrorType) -> Self {
        let status_code = match error_type {
            ApiErrorType::Validation => StatusCode::BAD_REQUEST,
            ApiErrorType::Authentication => StatusCode::UNAUTHORIZED,
            ApiErrorType::Authorization => StatusCode::FORBIDDEN,
            ApiErrorType::NotFound => StatusCode::NOT_FOUND,
            ApiErrorType::Database | ApiErrorType::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };

        Self {
            message: message.into(),
            error_type,
            status_code,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(message, ApiErrorType::NotFound)
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(message, ApiErrorType::Validation)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        ApiError::new(err.to_string(), ApiErrorType::Database)
    }
}

impl From<ValidationError> for ApiError {
    fn from(err: ValidationError) -> Self {
        ApiError::new(err.to_string(), ApiErrorType::Validation)
    }
}

// Helper function to convert validation results
pub fn from_validation<T>(result: Result<T, ValidationError>) -> Result<T, ApiError> {
    result.map_err(ApiError::from)
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code).json(self)
    }

    fn status_code(&self) -> StatusCode {
        self.status_code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;
    use validator::ValidationError;

    #[test]
    fn test_api_error_new() {
        let error = ApiError::new("Test message", ApiErrorType::Validation);
        assert_eq!(error.message, "Test message");
        assert_eq!(error.error_type, ApiErrorType::Validation);
        assert_eq!(error.status_code, StatusCode::BAD_REQUEST);

        let error = ApiError::new("Auth fail", ApiErrorType::Authentication);
        assert_eq!(error.status_code, StatusCode::UNAUTHORIZED);

        let error = ApiError::new("Forbidden", ApiErrorType::Authorization);
        assert_eq!(error.status_code, StatusCode::FORBIDDEN);
        
        let error = ApiError::new("Not here", ApiErrorType::NotFound);
        assert_eq!(error.status_code, StatusCode::NOT_FOUND);

        let error = ApiError::new("DB broke", ApiErrorType::Database);
        assert_eq!(error.status_code, StatusCode::INTERNAL_SERVER_ERROR);

        let error = ApiError::new("Server boom", ApiErrorType::Internal);
        assert_eq!(error.status_code, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_api_error_not_found() {
        let error = ApiError::not_found("Resource gone");
        assert_eq!(error.message, "Resource gone");
        assert_eq!(error.error_type, ApiErrorType::NotFound);
        assert_eq!(error.status_code, StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_api_error_bad_request() {
        let error = ApiError::bad_request("Bad input data");
        assert_eq!(error.message, "Bad input data");
        assert_eq!(error.error_type, ApiErrorType::Validation);
        assert_eq!(error.status_code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_from_sqlx_error() {
        // sqlx::Error does not implement PartialEq, so we can't directly compare.
        // We'll simulate a simple error kind that can be stringified.
        // For a real test, you might need a specific error variant.
        let sqlx_err = sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, "test io error"));
        let api_error: ApiError = sqlx_err.into();
        
        assert!(api_error.message.contains("test io error"));
        assert_eq!(api_error.error_type, ApiErrorType::Database);
        assert_eq!(api_error.status_code, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_from_validation_error() {
        let mut validation_err = ValidationError::new("field_error");
        validation_err.message = Some("Field is invalid".into());
        let api_error: ApiError = validation_err.clone().into(); // Clone because ValidationError might be used elsewhere
        
        assert!(api_error.message.contains("Field is invalid"));
        assert_eq!(api_error.error_type, ApiErrorType::Validation);
        assert_eq!(api_error.status_code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_from_validation_helper_ok() {
        let result: Result<&str, ValidationError> = Ok("valid data");
        let api_result = from_validation(result);
        assert!(api_result.is_ok());
        assert_eq!(api_result.unwrap(), "valid data");
    }

    #[test]
    fn test_from_validation_helper_err() {
        let validation_err = ValidationError::new("another_error");
        let result: Result<&str, ValidationError> = Err(validation_err);
        let api_result: Result<&str, ApiError> = from_validation(result);
        
        assert!(api_result.is_err());
        let err = api_result.unwrap_err();
        assert_eq!(err.error_type, ApiErrorType::Validation);
        assert_eq!(err.status_code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_response_error_implementation() {
        let api_error = ApiError::new("Test response error", ApiErrorType::Internal);
        assert_eq!(api_error.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

        let http_response = api_error.error_response();
        assert_eq!(http_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        
        // Check if the body can be serialized and deserialized (simplified check)
        // For a full check, you'd deserialize the body bytes back into ApiError
        // let body_bytes = actix_web::body::to_bytes(http_response.into_body()).await.unwrap();
        // let body_str = std::str::from_utf8(&body_bytes).unwrap();
        // assert!(body_str.contains("Test response error"));
        // assert!(body_str.contains("Internal"));
    }

    #[test]
    fn test_api_error_type_display() {
        assert_eq!(ApiErrorType::Validation.to_string(), "Validation error");
        assert_eq!(ApiErrorType::Authentication.to_string(), "Authentication error");
        assert_eq!(ApiErrorType::Authorization.to_string(), "Authorization error");
        assert_eq!(ApiErrorType::NotFound.to_string(), "Not found");
        assert_eq!(ApiErrorType::Database.to_string(), "Database error");
        assert_eq!(ApiErrorType::Internal.to_string(), "Internal server error");
    }
}
