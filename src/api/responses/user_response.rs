use serde::Serialize;

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            message: None,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: None,
            data: None,
            error: Some(message.into()),
        }
    }

    pub fn success_with_message(message: &str, data: T) -> Self {
        Self {
            success: true,
            message: Some(message.to_string()),
            data: Some(data),
            error: None,
        }
    }

    pub fn error_with_type(message: impl Into<String>, error_type: impl Into<String>) -> Self {
        Self {
            success: false,
            message: Some(message.into()),
            data: None,
            error: Some(error_type.into()),
        }
    }
}
