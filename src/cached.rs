use std::collections::HashSet;

use age::{DecryptError, EncryptError};
use age_core::format::{FileKey, Stanza};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use secrecy::ExposeSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::params::Argon2Params;

const STANZA_TAG: &str = "thesis.co/argon2";

/// Cached key material from a successful Argon2id decryption.
///
/// Contains everything needed to re-encrypt and re-decrypt without
/// running the KDF again. Stored in the OS keychain during a session.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CachedMaterial {
    /// The age FileKey (16 bytes)
    pub file_key: [u8; 16],
    /// The Argon2id-derived wrapping key (32 bytes)
    pub wrapping_key: [u8; 32],
    /// The salt used for key derivation (16 bytes)
    pub salt: [u8; 16],
    /// The Argon2id parameters used
    #[zeroize(skip)]
    pub params: Argon2Params,
}

/// Zero-KDF identity for session reads.
///
/// Returns the cached FileKey directly without any cryptographic operations.
pub struct CachedIdentity {
    file_key: [u8; 16],
}

impl CachedIdentity {
    pub fn new(material: &CachedMaterial) -> Self {
        Self {
            file_key: material.file_key,
        }
    }
}

impl Drop for CachedIdentity {
    fn drop(&mut self) {
        self.file_key.zeroize();
    }
}

impl age::Identity for CachedIdentity {
    /// Return the cached FileKey for any matching stanza.
    ///
    /// This intentionally skips body verification: the cached file key was
    /// already authenticated during the initial full-KDF `Argon2idIdentity`
    /// decryption. If the file key is wrong (e.g. corrupted keychain), the
    /// age STREAM layer will detect it via its per-chunk Poly1305 MAC and
    /// return a decryption error — no silent data corruption is possible.
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }

        Some(Ok(FileKey::new(Box::new(self.file_key))))
    }
}

/// Zero-KDF recipient for session writes.
///
/// Wraps the FileKey using the cached wrapping key and salt,
/// avoiding any Argon2id computation.
pub struct CachedRecipient {
    wrapping_key: [u8; 32],
    salt: [u8; 16],
    params: Argon2Params,
}

impl CachedRecipient {
    pub fn new(material: &CachedMaterial) -> Self {
        Self {
            wrapping_key: material.wrapping_key,
            salt: material.salt,
            params: material.params,
        }
    }
}

impl Drop for CachedRecipient {
    fn drop(&mut self) {
        self.wrapping_key.zeroize();
        self.salt.zeroize();
    }
}

impl age::Recipient for CachedRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        // Wrap FileKey using the cached wrapping key
        let body = age_core::primitives::aead_encrypt(&self.wrapping_key, file_key.expose_secret());

        let stanza = Stanza {
            tag: STANZA_TAG.to_string(),
            args: vec![
                STANDARD_NO_PAD.encode(self.salt),
                self.params.m_cost().to_string(),
                self.params.t_cost().to_string(),
                self.params.p_cost().to_string(),
            ],
            body,
        };

        // Same label pattern as Argon2idRecipient: must be only recipient
        let mut labels = HashSet::new();
        labels.insert(uuid::Uuid::new_v4().to_string());

        Ok((vec![stanza], labels))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Argon2idIdentity;
    use crate::recipient::Argon2idRecipient;
    use age::{Identity, Recipient};

    fn fast_params() -> Argon2Params {
        Argon2Params::new(256, 1, 1).unwrap()
    }

    #[test]
    fn test_cached_identity_returns_key_without_kdf() {
        let material = CachedMaterial {
            file_key: [42u8; 16],
            wrapping_key: [0u8; 32],
            salt: [0u8; 16],
            params: fast_params(),
        };

        let identity = CachedIdentity::new(&material);
        let stanza = Stanza {
            tag: "thesis.co/argon2".to_string(),
            args: vec![], // args not checked by CachedIdentity
            body: vec![], // body not checked by CachedIdentity
        };

        let result = identity.unwrap_stanza(&stanza).unwrap().unwrap();
        assert_eq!(result.expose_secret(), &[42u8; 16]);
    }

    #[test]
    fn test_cached_identity_ignores_wrong_tag() {
        let material = CachedMaterial {
            file_key: [42u8; 16],
            wrapping_key: [0u8; 32],
            salt: [0u8; 16],
            params: fast_params(),
        };

        let identity = CachedIdentity::new(&material);
        let stanza = Stanza {
            tag: "X25519".to_string(),
            args: vec![],
            body: vec![],
        };

        assert!(identity.unwrap_stanza(&stanza).is_none());
    }

    #[test]
    fn test_cached_recipient_produces_valid_stanza() {
        let material = CachedMaterial {
            file_key: [42u8; 16],
            wrapping_key: [99u8; 32],
            salt: [1u8; 16],
            params: fast_params(),
        };

        let recipient = CachedRecipient::new(&material);
        let file_key = FileKey::new(Box::new([42u8; 16]));

        let (stanzas, labels) = recipient.wrap_file_key(&file_key).unwrap();
        assert_eq!(stanzas.len(), 1);
        assert_eq!(stanzas[0].tag, "thesis.co/argon2");
        assert_eq!(stanzas[0].args.len(), 4);
        assert_eq!(stanzas[0].body.len(), 32);
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn test_cached_roundtrip_with_real_material() {
        // Full roundtrip: encrypt with KDF → capture material → decrypt with cached
        let passphrase = b"test-password";
        let params = fast_params();

        // Step 1: Encrypt with full KDF
        let recipient = Argon2idRecipient::new(passphrase, params);
        let original_key = FileKey::new(Box::new([42u8; 16]));
        let (stanzas, _) = recipient.wrap_file_key(&original_key).unwrap();

        // Step 2: Decrypt with full KDF and capture material
        let identity = Argon2idIdentity::new(passphrase);
        let decrypted = identity.unwrap_stanza(&stanzas[0]).unwrap().unwrap();
        assert_eq!(decrypted.expose_secret(), &[42u8; 16]);

        let material = identity.captured_material().unwrap();

        // Step 3: Re-encrypt with cached recipient
        let cached_recipient = CachedRecipient::new(&material);
        let rekey = FileKey::new(Box::new(material.file_key));
        let (new_stanzas, _) = cached_recipient.wrap_file_key(&rekey).unwrap();

        // Step 4: Decrypt with cached identity
        let cached_identity = CachedIdentity::new(&material);
        let result = cached_identity
            .unwrap_stanza(&new_stanzas[0])
            .unwrap()
            .unwrap();
        assert_eq!(result.expose_secret(), &[42u8; 16]);

        // Step 5: Also verify Argon2idIdentity can decrypt the cached stanza
        let full_identity = Argon2idIdentity::new(passphrase);
        let result2 = full_identity
            .unwrap_stanza(&new_stanzas[0])
            .unwrap()
            .unwrap();
        assert_eq!(result2.expose_secret(), &[42u8; 16]);
    }
}
