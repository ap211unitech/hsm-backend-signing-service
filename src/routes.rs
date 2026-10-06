use crate::crypto::Signer;
use crate::error::AppError;

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

pub type AppState = Arc<dyn Signer>;

#[derive(Deserialize)]
struct SignRequest {
    key_id: String,
    algorithm: String,
    payload: String,
}

#[derive(Serialize)]
struct SignResponse {
    key_id: String,
    algorithm: String,
    signature: String,
    duration_ms: u64,
}

async fn sign_handler(
    State(signer): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, AppError> {
    let start = Instant::now();

    if req.algorithm != "ECDSA_P256_SHA256" {
        return Err(AppError::UnsupportedAlgorithm);
    }

    let payload_bytes = STANDARD
        .decode(&req.payload)
        .map_err(|_| AppError::InvalidPayload)?;

    let signature_bytes = signer.sign(&req.key_id, &payload_bytes).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(Json(SignResponse {
        key_id: req.key_id,
        algorithm: req.algorithm,
        signature: STANDARD.encode(signature_bytes),
        duration_ms,
    }))
}

pub async fn healthz() -> &'static str {
    "ok"
}

pub fn router(pool: Arc<dyn Signer>) -> Router {
    let app = Router::new()
        .route("/v1/sign", post(sign_handler))
        .route("/healthz", get(healthz))
        .with_state(pool);

    app
}
