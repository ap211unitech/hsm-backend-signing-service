# Arkion HSM-Backed Signing Service

A robust, asynchronous Rust service providing cryptographic signing capabilities backed by a PKCS#11-compatible Hardware Security Module (HSM). This implementation utilizes Axum for the HTTP layer, Tokio for async runtime execution, and Cryptoki for PKCS#11 integration with SoftHSM2.

## Architectural Decisions & Abstractions

- **Transport & Concurrency:** Built on `axum` and `tokio` for asynchronous request handling.
- **Clean Abstraction:** The cryptographic layer is abstracted behind the `Signer` async trait. This allows seamless substitution between the `HsmSessionPool` (production) and the `MockSigner` (testing/fallback).
- **HSM Session Management:** PKCS#11 sessions are stateful, locking, and scarce. This service uses a bounded asynchronous object pool (`HsmSessionPool`) via Tokio channels. It bounds concurrency by checking out authenticated sessions, executing the signing operation, and returning the session to the pool, preventing token exhaustion and providing natural backpressure.
- **Key Security & Non-Exportability:** Both the ECDSA P-256 private key and the AES-256 symmetric key are generated strictly within the cryptographic boundary of the HSM with the `CKA_EXTRACTABLE` attribute set to `false`.
- **Symmetric Key Demonstration:** Upon initialization, the service generates an AES-256 key and performs an AES-GCM (or CBC) encryption/decryption validation loop internally to verify symmetric capabilities before accepting traffic.
- **Signature Verification:** After signing, the service immediately locates the corresponding public key and verifies the signature inside the HSM boundary before returning it to the client.

## Assume Arkion must issue 100,000 short-lived certificates per second... How would you design the CA/key hierarchy and signing infrastructure?

Issuing 100,000 leaf certificates/sec directly inside an HSM is physically impossible due to hardware cryptographic processing limits (typically capped at a few thousand asymmetric operations per second).

1. **Root CA & Intermediate CAs:** Keep the Root CA completely offline in an air-gapped physical HSM. Issue long-lived Intermediate CAs (ICAs) and store them in clustered network HSMs.
2. **Delegated Hybrid Signing:** We cannot do leaf signing directly in the HSM at 100k TPS. Instead, we use the HSM to issue ephemeral, short-lived intermediate delegations to highly scaled, stateless worker nodes operating in Trusted Execution Environments (TEEs) like AWS Nitro Enclaves.
3. **Key Wrapping:** Use the HSM for secure bulk symmetric key-wrapping. The HSM wraps the delegated signing keys, which are only unwrapped inside the memory-isolated TEE workers.
4. **Tradeoffs:** Software signing in TEEs provides horizontal scalability and geo-redundant failover capability at a fraction of the cost of scaling hardware tokens. The risk of software-signing is mitigated by the short TTL of the delegated keys and strict memory isolation.

## Benchmarks & Bottlenecks

**Command:** `oha -c <concurrency> -z 10s -m POST -T application/json -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"SGVsbG8="}' http://localhost:8080/v1/sign`

| Concurrency | Throughput (req/sec) | p50 (ms) | p95 (ms) | p99 (ms) | Error Rate |
| :---------: | -------------------: | -------: | -------: | -------: | ---------: |
|      1      |               ~2,246 |     0.42 |     0.54 |     0.85 |      0.00% |
|     10      |               ~5,483 |      1.7 |      2.8 |        4 |      0.00% |
|     100     |               ~5,748 |       16 |       33 |       43 |      0.00% |
|     500     |               ~5,759 |       78 |      167 |      215 |      0.00% |

**Observed Bottlenecks:**
The primary bottleneck is the locking mechanism inside SoftHSM2 and the bounded channel size (`pool_size = 10`) in the `HsmSessionPool`. At higher concurrency (100-500 callers), the Axum workers begin queuing for an available PKCS#11 session. This provides safe backpressure but causes tail latencies (p99) to increase proportionally to the queue length.

## Build and Run Instructions

1. **Build the container image:**
   `docker build -t hsm-backend-signing-service .`
2. **Run the container (exposes port 8080):**
   `docker run -p 8080:8080 hsm-backend-signing-service`
3. **Test the API:**
   ```bash
   curl -X POST http://localhost:8080/v1/sign \
     -H "Content-Type: application/json" \
     -d '{
       "key_id": "arkion-intermediate-prod",
       "algorithm": "ECDSA_P256_SHA256",
       "payload": "SGVsbG8sIEFya2lvbiE="
     }'
   ```
