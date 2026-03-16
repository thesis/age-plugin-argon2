#![warn(missing_docs)]

//! Argon2id recipient/identity plugin for the age encryption format.
//!
//! This crate provides password-based encryption for [age] files using Argon2id
//! key derivation instead of scrypt. It also provides cached variants that skip
//! the KDF entirely for session-based workflows.
//!
//! [age]: https://age-encryption.org
//!
//! # Quick start
//!
//! Full KDF encrypt → decrypt roundtrip:
//!
//! ```rust
//! use age_plugin_argon2::{Argon2idRecipient, Argon2idIdentity, Argon2Params};
//! use age::{Recipient, Identity};
//! use age_core::format::FileKey;
//! use secrecy::ExposeSecret;
//!
//! let passphrase = b"hunter2";
//! let params = Argon2Params::new(256, 1, 1).unwrap(); // use stronger params in production
//!
//! // Encrypt
//! let recipient = Argon2idRecipient::new(passphrase, params);
//! let file_key = FileKey::new(Box::new([0u8; 16]));
//! let (stanzas, _labels) = recipient.wrap_file_key(&file_key).unwrap();
//!
//! // Decrypt
//! let identity = Argon2idIdentity::new(passphrase);
//! let recovered = identity.unwrap_stanza(&stanzas[0]).unwrap().unwrap();
//! assert_eq!(recovered.expose_secret(), file_key.expose_secret());
//! ```
//!
//! # Cached / session mode
//!
//! After an initial KDF decryption, captured material can be reused to avoid
//! running Argon2id on every subsequent encrypt/decrypt:
//!
//! ```rust
//! use age_plugin_argon2::{Argon2idRecipient, Argon2idIdentity, CachedRecipient, CachedIdentity, Argon2Params};
//! use age::{Recipient, Identity};
//! use age_core::format::FileKey;
//! use secrecy::ExposeSecret;
//!
//! let passphrase = b"hunter2";
//! let params = Argon2Params::new(256, 1, 1).unwrap();
//!
//! // Initial full-KDF encrypt + decrypt to capture session material
//! let (stanzas, _) = Argon2idRecipient::new(passphrase, params)
//!     .wrap_file_key(&FileKey::new(Box::new([0u8; 16])))
//!     .unwrap();
//! let identity = Argon2idIdentity::new(passphrase);
//! identity.unwrap_stanza(&stanzas[0]).unwrap().unwrap();
//! let material = identity.captured_material().unwrap();
//!
//! // Session re-encrypt without running Argon2id
//! let session_key = FileKey::new(Box::new(material.file_key));
//! let (session_stanzas, _) = CachedRecipient::new(&material)
//!     .wrap_file_key(&session_key)
//!     .unwrap();
//!
//! // Session decrypt — also skips KDF
//! let recovered = CachedIdentity::new(&material)
//!     .unwrap_stanza(&session_stanzas[0])
//!     .unwrap()
//!     .unwrap();
//! assert_eq!(recovered.expose_secret(), &[0u8; 16]);
//! ```
//!
//! # Security model
//!
//! Two operational modes with different security/performance trade-offs:
//!
//! ## Full KDF (`Argon2idRecipient` / `Argon2idIdentity`)
//!
//! Used at session boundaries (init, unlock). Every encrypt/decrypt runs the
//! full Argon2id KDF to derive a wrapping key from the passphrase + random salt.
//! The wrapping key protects the age FileKey via ChaCha20-Poly1305 AEAD.
//!
//! - **Encrypt**: random salt → Argon2id → wrapping key → AEAD-wrap FileKey
//! - **Decrypt**: parse salt from stanza → Argon2id → wrapping key → AEAD-unwrap FileKey
//! - **Key capture**: on successful decrypt, `Argon2idIdentity` captures the
//!   FileKey + wrapping key + salt as [`CachedMaterial`] for session caching
//!
//! ## Cached / zero-KDF (`CachedRecipient` / `CachedIdentity`)
//!
//! Used during an active session after the initial unlock. The passphrase is
//! never stored — only opaque key material (64 bytes) lives in the OS keychain.
//!
//! - **`CachedRecipient`** (writes): reuses the captured wrapping key + salt to
//!   AEAD-wrap the FileKey without running Argon2id. Produces stanzas
//!   indistinguishable from full-KDF output.
//! - **`CachedIdentity`** (reads): returns the cached FileKey directly.
//!   Stanza body verification is intentionally skipped because the age STREAM
//!   layer provides per-chunk Poly1305 authentication — a wrong FileKey will
//!   fail at payload decryption, not silently produce garbage.
//!
//! ## Stanza format
//!
//! ```text
//! -> thesis.co/argon2 <base64-salt> <m_cost> <t_cost> <p_cost>
//! <AEAD-wrapped FileKey>
//! ```
//!
//! The namespaced tag (`thesis.co/argon2`) avoids collisions with any future
//! upstream age scrypt/argon2 recipient type.

/// Cached / zero-KDF recipient and identity for session use.
pub mod cached;
/// Low-level age-format encryption with a caller-supplied FileKey.
pub mod encrypt;
/// Full-KDF identity for passphrase-based decryption.
pub mod identity;
/// Validated Argon2id parameters.
pub mod params;
/// Full-KDF recipient for passphrase-based encryption.
pub mod recipient;

pub use cached::{CachedIdentity, CachedMaterial, CachedRecipient};
pub use encrypt::{encrypt_with_file_key, EncryptWithFileKeyError};
pub use identity::Argon2idIdentity;
pub use params::{Argon2Params, InvalidParams};
pub use recipient::Argon2idRecipient;
