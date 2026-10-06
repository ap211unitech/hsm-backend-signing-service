use crate::error::AppError;
use async_trait::async_trait;
use cryptoki::context::CInitializeFlags;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use p256::ecdsa::{Signature, SigningKey, signature::SignerMut};
use rand_core::OsRng;
use std::sync::Mutex;
use tracing::{error, info};

pub const KEY_LABEL: &str = "arkion-intermediate-prod";

#[async_trait]
pub trait Signer: Send + Sync {
    async fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, AppError>;
}

pub struct HsmSessionPool {
    pool: async_channel::Sender<Session>,
    receiver: async_channel::Receiver<Session>,
}

impl HsmSessionPool {
    pub fn new(lib_path: &str, pin: &str, pool_size: usize) -> Self {
        let pkcs11 = Pkcs11::new(lib_path).expect("Failed to load PKCS#11 library");

        let init_args = CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK);

        pkcs11
            .initialize(init_args)
            .expect("Failed to init PKCS#11");

        let slots = pkcs11.get_slots_with_token().expect("Failed to get slots");
        let slot = slots[0];

        let (sender, receiver) = async_channel::bounded(pool_size);

        for _ in 0..pool_size {
            let session = pkcs11
                .open_rw_session(slot)
                .expect("Failed to open session");
            let auth_pin = AuthPin::new(pin.into());
            session.login(UserType::User, Some(&auth_pin)).unwrap_or(());
            sender.try_send(session).unwrap();
        }

        Self::provision_keys(&pkcs11, slot, pin);

        Self {
            pool: sender,
            receiver,
        }
    }

    fn provision_keys(pkcs11: &Pkcs11, slot: Slot, pin: &str) {
        let session = pkcs11.open_rw_session(slot).unwrap();
        session
            .login(UserType::User, Some(&AuthPin::new(pin.into())))
            .unwrap_or(());

        // 1. Provision non-exportable ECDSA Key Pair
        if session
            .find_objects(&[Attribute::Label(KEY_LABEL.into())])
            .unwrap()
            .is_empty()
        {
            let pub_template = vec![
                Attribute::Token(true),
                Attribute::Verify(true),
                Attribute::Label(KEY_LABEL.into()),
                Attribute::EcParams(vec![
                    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
                ]), // secp256r1
            ];
            let priv_template = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sign(true),
                Attribute::Extractable(false),
                Attribute::Label(KEY_LABEL.into()),
            ];
            session
                .generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template)
                .unwrap();
            info!("Generated non-exportable ECDSA P-256 key pair");
        }

        // 2. Provision non-exportable AES Key & demonstrate crypto op
        if session
            .find_objects(&[Attribute::Label("arkion-aes-key".into())])
            .unwrap()
            .is_empty()
        {
            let aes_template = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::ValueLen(32.into()), // AES-256
                Attribute::Extractable(false),
                Attribute::Label("arkion-aes-key".into()),
            ];
            let aes_key = session
                .generate_key(&Mechanism::AesKeyGen, &aes_template)
                .unwrap();

            let iv = [0u8; 16];
            let plaintext = b"Sensitive Token Data";
            let ciphertext = session
                .encrypt(&Mechanism::AesCbcPad(iv), aes_key, plaintext)
                .unwrap();
            let decrypted = session
                .decrypt(&Mechanism::AesCbcPad(iv), aes_key, &ciphertext)
                .unwrap();

            assert_eq!(plaintext.as_slice(), decrypted.as_slice());
            info!("Validated symmetric AES encryption/decryption inside HSM boundary");
        }
    }
}

#[async_trait]
impl Signer for HsmSessionPool {
    async fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, AppError> {
        let session = self.receiver.recv().await.map_err(|_| AppError::HsmError)?;

        // Find private key
        let priv_template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Label(key_id.into()),
        ];
        let priv_objects = session
            .find_objects(&priv_template)
            .map_err(|_| AppError::HsmError)?;
        let key_handle = *priv_objects.first().ok_or(AppError::KeyNotFound)?;

        // Sign payload
        let signature = session
            .sign(&Mechanism::Ecdsa, key_handle, payload)
            .map_err(|e| {
                error!("HSM signing error: {}", e);
                AppError::HsmError
            })?;

        // Find public key & Verify
        let pub_template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Label(key_id.into()),
        ];
        let pub_objects = session
            .find_objects(&pub_template)
            .map_err(|_| AppError::HsmError)?;
        let pub_key_handle = *pub_objects.first().ok_or(AppError::KeyNotFound)?;

        session
            .verify(&Mechanism::Ecdsa, pub_key_handle, payload, &signature)
            .map_err(|e| {
                error!("Signature verification failed: {}", e);
                AppError::HsmError
            })?;

        let _ = self.pool.send(session).await;
        Ok(signature)
    }
}

// Mock implementation for clean substitution
pub struct MockSigner {
    signing_key: Mutex<SigningKey>,
}

impl MockSigner {
    pub fn new() -> Self {
        Self {
            signing_key: Mutex::new(SigningKey::random(&mut OsRng)),
        }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.signing_key
            .lock()
            .unwrap()
            .verifying_key()
            .to_sec1_bytes()
            .to_vec()
    }
}

impl Default for MockSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Signer for MockSigner {
    async fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, AppError> {
        if key_id != KEY_LABEL {
            return Err(AppError::KeyNotFound);
        }

        let mut guard = self.signing_key.lock().unwrap();
        let signature: Signature = guard.sign(payload);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
