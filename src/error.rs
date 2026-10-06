use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("HSM operation failed internal lock")]
    HsmError,
    #[error("Key identifier not provisioned")]
    KeyNotFound,
    #[error("Payload cannot be processed")]
    InvalidPayload,
    #[error("Requested cryptographic algorithm is unsupported")]
    UnsupportedAlgorithm,
}

impl AppError {
    pub fn status(&self) -> u16 {
        match self {
            AppError::HsmError => 500,
            AppError::KeyNotFound => 404,
            AppError::InvalidPayload => 400,
            AppError::UnsupportedAlgorithm => 400,
        }
    }

    pub fn client_message(&self) -> &'static str {
        match self {
            AppError::HsmError => "Internal server error",
            AppError::KeyNotFound => "Key not found",
            AppError::InvalidPayload => "Invalid Base64 payload",
            AppError::UnsupportedAlgorithm => "Algorithm not supported",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = serde_json::json!({
            "error": self.client_message()
        });

        let mut response = axum::Json(body).into_response();
        *response.status_mut() = status;

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        assert_eq!(AppError::HsmError.status(), 500);
        assert_eq!(AppError::KeyNotFound.status(), 404);
        assert_eq!(AppError::InvalidPayload.status(), 400);
        assert_eq!(AppError::UnsupportedAlgorithm.status(), 400);
    }
}
