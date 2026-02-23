//! Custom age-format writer that accepts a known FileKey.
//!
//! Since `age::Encryptor` generates a random FileKey internally and doesn't
//! expose it, we need a custom encrypt function to reuse a cached FileKey.
//! This produces spec-compliant age v1 binary files.

use std::io::Write;

use age::Recipient;
use age_core::format::FileKey;
use base64::Engine;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::Mac;
use rand::rngs::OsRng;
use rand::RngCore;

/// Encrypt plaintext using a known FileKey + recipient.
///
/// Produces a standard age v1 binary format file that can be decrypted
/// by any age-compatible tool with the matching identity.
///
/// # Safety
///
/// Reusing the same FileKey + salt across writes is safe because:
/// - The stanza wrapping is deterministic (same inputs, same output)
/// - The STREAM layer gets a fresh random 16-byte nonce each write
pub fn encrypt_with_file_key(
    file_key: &[u8; 16],
    recipient: &impl Recipient,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptWithFileKeyError> {
    let fk = FileKey::new(Box::new(*file_key));

    // 1. Wrap the file key with the recipient
    let (stanzas, _labels) = recipient
        .wrap_file_key(&fk)
        .map_err(|e| EncryptWithFileKeyError::Wrap(e.to_string()))?;

    // 2. Build the header (everything covered by the MAC)
    // Per age spec: MAC covers from "age-encryption.org/v1\n" through "---" inclusive
    let mut header = Vec::new();
    header.extend_from_slice(b"age-encryption.org/v1\n");

    for stanza in &stanzas {
        // Write stanza: -> tag arg1 arg2 ...
        write!(header, "-> {}", stanza.tag)
            .map_err(|e| EncryptWithFileKeyError::Io(e.to_string()))?;
        for arg in &stanza.args {
            write!(header, " {}", arg).map_err(|e| EncryptWithFileKeyError::Io(e.to_string()))?;
        }
        header.push(b'\n');

        // Write body lines (base64, 64 chars per line)
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&stanza.body);
        let mut remaining = encoded.as_str();
        loop {
            if remaining.len() >= 64 {
                let (line, rest) = remaining.split_at(64);
                header.extend_from_slice(line.as_bytes());
                header.push(b'\n');
                remaining = rest;
            } else {
                // Final short line (may be empty if encoded was multiple of 64)
                header.extend_from_slice(remaining.as_bytes());
                header.push(b'\n');
                break;
            }
        }
    }

    // Append "---" to the MAC input (per spec: MAC covers through "---" inclusive)
    header.extend_from_slice(b"---");

    // 3. Compute header MAC
    // MAC key = HKDF-SHA256(ikm=file_key, salt="", info="header")
    let mac_key = age_core::primitives::hkdf(&[], b"header", file_key);

    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(&mac_key)
        .map_err(|_| EncryptWithFileKeyError::Crypto("invalid MAC key length".to_string()))?;
    mac.update(&header);

    let mac_result = mac.finalize().into_bytes();
    let mac_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(mac_result);

    // 4. Build complete output
    // The actual file has: header_without_dashes + "--- " + mac_b64 + "\n" + payload
    let mut output = Vec::new();
    // Write everything except the trailing "---" that we added for MAC computation
    output.extend_from_slice(&header[..header.len() - 3]);
    // Write the MAC line: "--- <mac>\n"
    writeln!(output, "--- {}", mac_b64).map_err(|e| EncryptWithFileKeyError::Io(e.to_string()))?;

    // 5. Generate 16-byte random nonce for the payload
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    output.extend_from_slice(&nonce);

    // 6. Derive payload key: HKDF-SHA256(salt=nonce, info="payload", ikm=file_key)
    let payload_key = age_core::primitives::hkdf(&nonce, b"payload", file_key);

    // 7. STREAM encryption — single final chunk
    // age uses a custom STREAM construction:
    // - ChaCha20-Poly1305 with a 12-byte nonce
    // - Nonce = 11 bytes counter (big-endian) + 1 byte flag
    // - For a single final chunk: counter=0, flag=0x01 (final)
    let mut stream_nonce = [0u8; 12];
    stream_nonce[11] = 0x01; // last_chunk flag

    let cipher = ChaCha20Poly1305::new_from_slice(&payload_key)
        .map_err(|e| EncryptWithFileKeyError::Crypto(e.to_string()))?;

    let mut ciphertext = plaintext.to_vec();
    cipher
        .encrypt_in_place(
            chacha20poly1305::Nonce::from_slice(&stream_nonce),
            &[],
            &mut ciphertext,
        )
        .map_err(|e| EncryptWithFileKeyError::Crypto(e.to_string()))?;

    output.extend_from_slice(&ciphertext);

    Ok(output)
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptWithFileKeyError {
    #[error("failed to wrap file key: {0}")]
    Wrap(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("cryptographic error: {0}")]
    Crypto(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cached::{CachedIdentity, CachedRecipient};
    use crate::identity::Argon2idIdentity;
    use crate::params::Argon2Params;
    use crate::recipient::Argon2idRecipient;

    fn fast_params() -> Argon2Params {
        Argon2Params::new(256, 1, 1).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_with_full_kdf() {
        let passphrase = b"test-password";
        let params = fast_params();

        // Encrypt with full KDF recipient
        let recipient = Argon2idRecipient::new(passphrase, params);
        let file_key = [42u8; 16];
        let plaintext = b"hello, world!";

        let ciphertext = encrypt_with_file_key(&file_key, &recipient, plaintext).unwrap();

        // Decrypt with full KDF identity
        let identity = Argon2idIdentity::new(passphrase);
        let decrypted = age::decrypt(&identity, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_cached_material() {
        let passphrase = b"test-password";
        let params = fast_params();

        // First: normal encrypt+decrypt to capture material
        let recipient = Argon2idRecipient::new(passphrase, params);
        let file_key_bytes = [42u8; 16];
        let plaintext = b"sensitive data here";

        let ciphertext = encrypt_with_file_key(&file_key_bytes, &recipient, plaintext).unwrap();

        let identity = Argon2idIdentity::new(passphrase);
        let decrypted = age::decrypt(&identity, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        let material = identity.captured_material().unwrap();

        // Now: re-encrypt with cached recipient + custom writer
        let cached_recipient = CachedRecipient::new(&material);
        let new_plaintext = b"updated data";

        let new_ciphertext =
            encrypt_with_file_key(&material.file_key, &cached_recipient, new_plaintext).unwrap();

        // Decrypt with cached identity
        let cached_identity = CachedIdentity::new(&material);
        let result = age::decrypt(&cached_identity, &new_ciphertext).unwrap();
        assert_eq!(result, new_plaintext);
    }

    #[test]
    fn test_output_is_valid_age_format() {
        let passphrase = b"test";
        let params = fast_params();
        let recipient = Argon2idRecipient::new(passphrase, params);
        let file_key = [1u8; 16];

        let ciphertext = encrypt_with_file_key(&file_key, &recipient, b"test data").unwrap();

        // The output should start with the age header
        assert!(ciphertext.starts_with(b"age-encryption.org/v1\n"));

        // And be decryptable by the standard age library
        let identity = Argon2idIdentity::new(passphrase);
        let result = age::decrypt(&identity, &ciphertext).unwrap();
        assert_eq!(result, b"test data");
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let passphrase = b"test";
        let params = fast_params();
        let recipient = Argon2idRecipient::new(passphrase, params);
        let file_key = [1u8; 16];

        let ciphertext = encrypt_with_file_key(&file_key, &recipient, b"").unwrap();

        let identity = Argon2idIdentity::new(passphrase);
        let result = age::decrypt(&identity, &ciphertext).unwrap();
        assert_eq!(result, b"");
    }
}
