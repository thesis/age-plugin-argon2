//! Argon2id recipient/identity plugin for the age encryption format.
//!
//! This crate provides password-based encryption for age files using Argon2id
//! key derivation instead of scrypt. It also provides cached variants that
//! skip the KDF entirely for session-based workflows.
//!
//! # Security Model
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
//! ## Cached / Zero-KDF (`CachedRecipient` / `CachedIdentity`)
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
//! ## Stanza Format
//!
//! ```text
//! -> thesis.co/argon2 <base64-salt> <m_cost> <t_cost> <p_cost>
//! <AEAD-wrapped FileKey>
//! ```
//!
//! The namespaced tag (`thesis.co/argon2`) avoids collisions with any future
//! upstream age scrypt/argon2 recipient type.

pub mod cached;
pub mod encrypt;
pub mod identity;
pub mod params;
pub mod recipient;

pub use cached::{CachedIdentity, CachedMaterial, CachedRecipient};
pub use encrypt::{encrypt_with_file_key, EncryptWithFileKeyError};
pub use identity::Argon2idIdentity;
pub use params::{Argon2Params, InvalidParams};
pub use recipient::Argon2idRecipient;
