//! Argon2id recipient/identity plugin for the age encryption format.
//!
//! This crate provides password-based encryption for age files using Argon2id
//! key derivation instead of scrypt. It also provides cached variants that
//! skip the KDF entirely for session-based workflows.

pub mod cached;
pub mod encrypt;
pub mod identity;
pub mod params;
pub mod recipient;

pub use cached::{CachedIdentity, CachedMaterial, CachedRecipient};
pub use encrypt::{encrypt_with_file_key, EncryptWithFileKeyError};
pub use identity::Argon2idIdentity;
pub use params::Argon2Params;
pub use recipient::Argon2idRecipient;
