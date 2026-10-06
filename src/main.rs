mod crypto;
mod error;
mod routes;

use std::env;
use std::sync::Arc;
use tracing::info;

use crate::crypto::HsmSessionPool;
use crate::routes::router;

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

    let app = router(hsm_pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    info!("Arkion Signing Service listening on 0.0.0.0:8080");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received, draining");
        })
        .await
        .unwrap();
}
