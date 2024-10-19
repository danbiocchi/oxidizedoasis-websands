use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use derive_more::Display;
use serde::Serialize;

#[derive(Debug, Display, Serialize)]
#[display(fmt = "{}", message)]
pub struct ApiError {
    pub message: String,
    pub error_type: ApiErrorType,
    #[serde(skip_serializing)]
    pub status_code: StatusCode,
}

#[derive(Debug, Display, Serialize)]
pub enum ApiErrorType {
    #[display(fmt = "Validation error")]
    Validation,
    #[display(fmt = "Authentication error")]
    Authentication,
    #[display(fmt = "Authorization error")]
    Authorization,
    #[display(fmt = "Not found")]
    NotFound,
    #[display(fmt = "Database error")]
    Database,
    #[display(fmt = "Internal server error")]
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
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code).json(self)
    }

    fn status_code(&self) -> StatusCode {
        self.status_code
    }
}