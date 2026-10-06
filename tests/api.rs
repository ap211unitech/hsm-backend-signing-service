#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use http_body_util::BodyExt;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tower::ServiceExt;

    use hsm_backend_signing_service::{
        crypto::{KEY_LABEL, MockSigner},
        routes::router,
    };

    /// Helper to send a POST request to `/v1/sign` and parse status and JSON output
    async fn post_sign(app: &Router, body: Value) -> (StatusCode, Value) {
        let req = Request::post("/v1/sign")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json_val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

        (status, json_val)
    }

    /// Helper constructor for test request JSON payloads
    fn body(key: &str, alg: &str, payload: &str) -> Value {
        json!({
            "key_id": key,
            "algorithm": alg,
            "payload": payload
        })
    }

    #[tokio::test]
    async fn happy_path_has_spec_shape_and_valid_signature() {
        let mock = Arc::new(MockSigner::new());
        let test_app = router(mock.clone());

        let raw_bytes = b"hello world payload";
        let encoded_payload = STANDARD.encode(raw_bytes);

        let (status, resp_body) = post_sign(
            &test_app,
            body(KEY_LABEL, "ECDSA_P256_SHA256", &encoded_payload),
        )
        .await;

        // 1. Assert response status and schema properties
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp_body["key_id"], KEY_LABEL);
        assert_eq!(resp_body["algorithm"], "ECDSA_P256_SHA256");
        assert!(resp_body["duration_ms"].is_u64());

        // 2. Decode returned signature and verify against mock's public key
        let sig_der_bytes = STANDARD
            .decode(resp_body["signature"].as_str().unwrap())
            .expect("Signature must be valid Base64");

        let verifying_key = VerifyingKey::from_sec1_bytes(&mock.public_key())
            .expect("Public key must be valid SEC1 format");

        let parsed_signature = Signature::from_der(&sig_der_bytes)
            .expect("Signature must be valid ASN.1 DER ECDSA format");

        assert!(
            verifying_key.verify(raw_bytes, &parsed_signature).is_ok(),
            "Cryptographic signature verification failed for payload"
        );
    }

    #[tokio::test]
    async fn unsupported_algorithm_is_400() {
        let mock = Arc::new(MockSigner::new());
        let test_app = router(mock);

        let (status, resp_body) = post_sign(&test_app, body(KEY_LABEL, "RSA_PSS", "aGk=")).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp_body["error"], "Algorithm not supported");
    }

    #[tokio::test]
    async fn bad_base64_is_400() {
        let mock = Arc::new(MockSigner::new());
        let test_app = router(mock);

        let (status, resp_body) = post_sign(
            &test_app,
            body(KEY_LABEL, "ECDSA_P256_SHA256", "!!not-valid-base64!!"),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp_body["error"], "Invalid Base64 payload");
    }

    #[tokio::test]
    async fn unknown_key_is_404() {
        let mock = Arc::new(MockSigner::new());
        let test_app = router(mock);

        let (status, resp_body) = post_sign(
            &test_app,
            body("non-existent-key", "ECDSA_P256_SHA256", "aGk="),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(resp_body["error"], "Key not found");
    }

    #[tokio::test]
    async fn malformed_json_is_rejected_not_500() {
        let mock = Arc::new(MockSigner::new());
        let test_app = router(mock);

        let req = Request::post("/v1/sign")
            .header("content-type", "application/json")
            .body(Body::from("{ malformed json string"))
            .unwrap();

        let response = test_app.oneshot(req).await.unwrap();

        assert!(
            response.status().is_client_error(),
            "Malformed JSON must return HTTP 4xx status instead of 500"
        );
    }

    #[tokio::test]
    async fn missing_field_is_rejected() {
        let mock = Arc::new(MockSigner::new());
        let test_app = router(mock);

        // Omit mandatory 'payload' and 'algorithm' fields
        let partial_json = json!({ "key_id": KEY_LABEL });

        let (status, _) = post_sign(&test_app, partial_json).await;

        assert!(
            status.is_client_error(),
            "Missing fields must return HTTP 4xx client error"
        );
    }
}
