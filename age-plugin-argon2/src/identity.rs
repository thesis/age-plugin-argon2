use std::cell::RefCell;

use age::DecryptError;
use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use secrecy::ExposeSecret;
use zeroize::Zeroize;

use crate::cached::CachedMaterial;
use crate::params::Argon2Params;
use crate::recipient::derive_wrapping_key;

const STANZA_TAG: &str = "thesis.co/argon2";

/// Argon2id identity — full KDF decryption path.
///
/// Used during `kin unlock` to validate the passphrase and derive key material.
/// After successful decryption, captured material can be retrieved for session caching.
pub struct Argon2idIdentity {
    passphrase: Vec<u8>,
    captured: RefCell<Option<CachedMaterial>>,
}

impl Argon2idIdentity {
    /// Create a new identity from a passphrase.
    pub fn new(passphrase: &[u8]) -> Self {
        Self {
            passphrase: passphrase.to_vec(),
            captured: RefCell::new(None),
        }
    }

    /// Retrieve the captured key material after a successful decryption.
    ///
    /// Returns `Some(CachedMaterial)` if `unwrap_stanza` succeeded, `None` otherwise.
    pub fn captured_material(&self) -> Option<CachedMaterial> {
        self.captured.borrow().clone()
    }
}

impl age::Identity for Argon2idIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        // 1. Check tag
        if stanza.tag != STANZA_TAG {
            return None;
        }

        // 2. Parse args: salt(b64), m_cost, t_cost, p_cost
        if stanza.args.len() != 4 {
            return Some(Err(DecryptError::InvalidHeader));
        }

        let salt = match STANDARD_NO_PAD.decode(&stanza.args[0]) {
            Ok(s) if s.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&s);
                arr
            }
            _ => return Some(Err(DecryptError::InvalidHeader)),
        };

        let m_cost = match stanza.args[1].parse::<u32>() {
            Ok(v) => v,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };
        let t_cost = match stanza.args[2].parse::<u32>() {
            Ok(v) => v,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };
        let p_cost = match stanza.args[3].parse::<u32>() {
            Ok(v) => v,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };

        let params = match Argon2Params::new(m_cost, t_cost, p_cost) {
            Ok(p) => p,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };

        // 3. Validate body length (16 file key + 16 poly1305 tag = 32)
        if stanza.body.len() != FILE_KEY_BYTES + 16 {
            return Some(Err(DecryptError::InvalidHeader));
        }

        // 4. Derive wrapping key
        let wrapping_key = match derive_wrapping_key(&self.passphrase, &salt, &params) {
            Ok(k) => k,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };

        // 5. AEAD-unwrap the file key
        let mut plaintext =
            match age_core::primitives::aead_decrypt(&wrapping_key, FILE_KEY_BYTES, &stanza.body) {
                Ok(pt) => pt,
                Err(_) => return Some(Err(DecryptError::KeyDecryptionFailed)),
            };

        // 6. Build FileKey and capture material
        let file_key = FileKey::init_with_mut(|fk| {
            fk.copy_from_slice(&plaintext);
            plaintext.zeroize();
        });

        // 7. Capture material for session caching
        let mut file_key_bytes = [0u8; 16];
        file_key_bytes.copy_from_slice(file_key.expose_secret());

        *self.captured.borrow_mut() = Some(CachedMaterial {
            file_key: file_key_bytes,
            wrapping_key,
            salt,
            params,
        });

        Some(Ok(file_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipient::Argon2idRecipient;
    use age::{Identity, Recipient};

    fn fast_params() -> Argon2Params {
        Argon2Params::new(256, 1, 1).unwrap()
    }

    #[test]
    fn test_wrap_then_unwrap_roundtrip() {
        let passphrase = b"test-password";
        let params = fast_params();

        let recipient = Argon2idRecipient::new(passphrase, params);
        let file_key = FileKey::new(Box::new([42u8; 16]));

        let (stanzas, _labels) = recipient.wrap_file_key(&file_key).unwrap();
        assert_eq!(stanzas.len(), 1);

        let identity = Argon2idIdentity::new(passphrase);
        let result = identity.unwrap_stanza(&stanzas[0]);

        let unwrapped = result.unwrap().unwrap();
        assert_eq!(unwrapped.expose_secret(), &[42u8; 16]);
    }

    #[test]
    fn test_wrong_passphrase_returns_err() {
        let params = fast_params();

        let recipient = Argon2idRecipient::new(b"correct", params);
        let file_key = FileKey::new(Box::new([42u8; 16]));
        let (stanzas, _) = recipient.wrap_file_key(&file_key).unwrap();

        let identity = Argon2idIdentity::new(b"wrong");
        let result = identity.unwrap_stanza(&stanzas[0]);

        assert!(matches!(
            result,
            Some(Err(DecryptError::KeyDecryptionFailed))
        ));
    }

    #[test]
    fn test_wrong_tag_returns_none() {
        let identity = Argon2idIdentity::new(b"test");
        let stanza = Stanza {
            tag: "X25519".to_string(),
            args: vec![],
            body: vec![],
        };

        assert!(identity.unwrap_stanza(&stanza).is_none());
    }

    #[test]
    fn test_captured_material() {
        let passphrase = b"test-password";
        let params = fast_params();

        let recipient = Argon2idRecipient::new(passphrase, params);
        let file_key = FileKey::new(Box::new([42u8; 16]));
        let (stanzas, _) = recipient.wrap_file_key(&file_key).unwrap();

        let identity = Argon2idIdentity::new(passphrase);

        // Before decryption, no material
        assert!(identity.captured_material().is_none());

        // Decrypt
        identity.unwrap_stanza(&stanzas[0]).unwrap().unwrap();

        // After decryption, material is captured
        let material = identity.captured_material().unwrap();
        assert_eq!(material.file_key, [42u8; 16]);
        assert_eq!(material.params, params);
    }
}
