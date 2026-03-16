use std::collections::HashSet;

use age::EncryptError;
use age_core::format::{FileKey, Stanza};
use argon2::{Algorithm, Argon2, Version};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::params::Argon2Params;

const STANZA_TAG: &str = "thesis.co/argon2";

/// Argon2id recipient — full KDF encryption path.
///
/// Used during `kin init` and when no cached material is available.
/// Generates a random salt, derives a wrapping key via Argon2id,
/// and wraps the FileKey using ChaCha20-Poly1305 (via age's AEAD primitives).
pub struct Argon2idRecipient {
    passphrase: Vec<u8>,
    params: Argon2Params,
}

impl Argon2idRecipient {
    /// Create a new recipient from a passphrase and Argon2id parameters.
    pub fn new(passphrase: &[u8], params: Argon2Params) -> Self {
        Self {
            passphrase: passphrase.to_vec(),
            params,
        }
    }
}

impl age::Recipient for Argon2idRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        // 1. Generate 16-byte random salt
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // 2. Derive 32-byte wrapping key via Argon2id
        let wrapping_key = derive_wrapping_key(&self.passphrase, &salt, &self.params)?;

        // 3. Wrap FileKey using age's AEAD
        let body = age_core::primitives::aead_encrypt(&wrapping_key, file_key.expose_secret());

        // 4. Build stanza
        let stanza = Stanza {
            tag: STANZA_TAG.to_string(),
            args: vec![
                STANDARD_NO_PAD.encode(salt),
                self.params.m_cost().to_string(),
                self.params.t_cost().to_string(),
                self.params.p_cost().to_string(),
            ],
            body,
        };

        // 5. Random UUID label — enforces "must be only recipient"
        let mut labels = HashSet::new();
        labels.insert(Uuid::new_v4().to_string());

        Ok((vec![stanza], labels))
    }
}

/// Derive a 32-byte wrapping key from a passphrase and salt using Argon2id.
///
/// Returns `Err` if the Argon2 parameters are invalid or hashing fails.
pub(crate) fn derive_wrapping_key(
    passphrase: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<[u8; 32], age::EncryptError> {
    let argon2_params =
        argon2::Params::new(params.m_cost(), params.t_cost(), params.p_cost(), Some(32)).map_err(
            |e| age::EncryptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)),
        )?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| {
            age::EncryptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::Recipient;

    #[test]
    fn test_derive_wrapping_key_deterministic() {
        let passphrase = b"test-password";
        let salt = [1u8; 16];
        let params = Argon2Params::new(256, 1, 1).unwrap();

        let key1 = derive_wrapping_key(passphrase, &salt, &params).unwrap();
        let key2 = derive_wrapping_key(passphrase, &salt, &params).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_wrap_file_key_produces_valid_stanza() {
        let recipient = Argon2idRecipient::new(b"test", Argon2Params::new(256, 1, 1).unwrap());

        let file_key = FileKey::new(Box::new([42u8; 16]));
        let (stanzas, labels) = recipient.wrap_file_key(&file_key).unwrap();

        assert_eq!(stanzas.len(), 1);
        assert_eq!(stanzas[0].tag, "thesis.co/argon2");
        assert_eq!(stanzas[0].args.len(), 4);
        // body = 16 bytes file key + 16 bytes poly1305 tag = 32 bytes
        assert_eq!(stanzas[0].body.len(), 32);
        // Exactly one label (UUID)
        assert_eq!(labels.len(), 1);
    }
}
