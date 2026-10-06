mod crypto;
mod error;

use axum::{Json, Router, extract::State, routing::post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use crypto::{HsmSessionPool, Signer};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

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

type AppState = Arc<dyn Signer>;

async fn sign_handler(
    State(signer): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, error::AppError> {
    let start = Instant::now();

    if req.algorithm != "ECDSA_P256_SHA256" {
        return Err(error::AppError::UnsupportedAlgorithm);
    }

    let payload_bytes = STANDARD
        .decode(&req.payload)
        .map_err(|_| error::AppError::InvalidPayload)?;

    let signature_bytes = signer.sign(&req.key_id, &payload_bytes).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(Json(SignResponse {
        key_id: req.key_id,
        algorithm: req.algorithm,
        signature: STANDARD.encode(signature_bytes),
        duration_ms,
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let lib_path =
        env::var("PKCS11_LIB_PATH").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".into());
    let pin = env::var("HSM_PIN").unwrap_or_else(|_| "1234".into());
    let pool_size = 10;

    info!(
        "Initializing HSM session pool with {} concurrent sessions",
        pool_size
    );
    let hsm_pool = Arc::new(HsmSessionPool::new(&lib_path, &pin, pool_size));

    let app = Router::new()
        .route("/v1/sign", post(sign_handler))
        .with_state(hsm_pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    info!("Arkion Signing Service listening on 0.0.0.0:8080");

    axum::serve(listener, app).await.unwrap();
}
