use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("HSM operation failed")]
    HsmError,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Invalid payload")]
    InvalidPayload,
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            Self::HsmError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Cryptographic operation failed",
            ),
            Self::KeyNotFound => (StatusCode::NOT_FOUND, "Requested key ID not found"),
            Self::InvalidPayload => (StatusCode::BAD_REQUEST, "Invalid Base64 payload"),
            Self::UnsupportedAlgorithm => (StatusCode::BAD_REQUEST, "Algorithm not supported"),
        };

        (status, Json(json!({ "error": msg }))).into_response()
    }
}
