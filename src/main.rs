use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

type AppState = Arc<dyn Signer>;

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
}
