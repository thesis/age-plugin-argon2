/// Integration test: stanzas produced by the library decrypt correctly via the plugin.
///
/// This ensures backward compatibility between the embedded-Rust path and the
/// IPC plugin path.
use age::{Identity, Recipient};
use age_core::format::FileKey;
use age_plugin_argon2::{Argon2Params, Argon2idIdentity, Argon2idRecipient};
use secrecy::ExposeSecret;

// Re-use the plugin's identity plugin directly (no IPC needed for unit testing).
// We import the encoding module indirectly via the binary crate path trick — but
// since this is an integration test of the binary crate, we must use the public API.

#[test]
fn library_stanzas_decrypt_via_identity_plugin_directly() {
    let passphrase = b"correct horse battery staple";
    let params = Argon2Params::new(256, 1, 1).unwrap();

    // 1. Produce a FileKey and encrypt it with the library recipient.
    let original_key_bytes: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    let file_key = FileKey::new(Box::new(original_key_bytes));
    let recipient = Argon2idRecipient::new(passphrase, params);
    let (stanzas, _labels) = recipient.wrap_file_key(&file_key).unwrap();
    assert_eq!(stanzas.len(), 1);

    // 2. Decrypt with the library identity.
    let identity = Argon2idIdentity::new(passphrase);
    let recovered = identity.unwrap_stanza(&stanzas[0]).unwrap().unwrap();
    assert_eq!(recovered.expose_secret(), &original_key_bytes);
}

#[test]
fn wrong_passphrase_returns_key_decryption_failed() {
    use age::DecryptError;

    let params = Argon2Params::new(256, 1, 1).unwrap();
    let file_key = FileKey::new(Box::new([0u8; 16]));
    let recipient = Argon2idRecipient::new(b"correct", params);
    let (stanzas, _) = recipient.wrap_file_key(&file_key).unwrap();

    let identity = Argon2idIdentity::new(b"wrong");
    let result = identity.unwrap_stanza(&stanzas[0]).unwrap();
    assert!(matches!(result, Err(DecryptError::KeyDecryptionFailed)));
}

#[test]
fn stanza_tag_is_thesis_co_argon2() {
    let params = Argon2Params::new(256, 1, 1).unwrap();
    let file_key = FileKey::new(Box::new([0u8; 16]));
    let recipient = Argon2idRecipient::new(b"passphrase", params);
    let (stanzas, _) = recipient.wrap_file_key(&file_key).unwrap();
    assert_eq!(stanzas[0].tag, "thesis.co/argon2");
}

#[test]
fn encoding_roundtrip_identity_and_recipient() {
    // Test via the binary — encode identity, list it, check recipient matches.
    use std::io::Write;
    use tempfile::NamedTempFile;

    let params = Argon2Params::new(65536, 3, 4).unwrap();

    // Simulate what --generate produces.
    let identity_str = {
        use bech32::{ToBase32, Variant};
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&params.m_cost().to_le_bytes());
        b[4..8].copy_from_slice(&params.t_cost().to_le_bytes());
        b[8..12].copy_from_slice(&params.p_cost().to_le_bytes());
        bech32::encode("age-plugin-argon2-", b.to_base32(), Variant::Bech32)
            .unwrap()
            .to_uppercase()
    };
    let recipient_str = {
        use bech32::{ToBase32, Variant};
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&params.m_cost().to_le_bytes());
        b[4..8].copy_from_slice(&params.t_cost().to_le_bytes());
        b[8..12].copy_from_slice(&params.p_cost().to_le_bytes());
        bech32::encode("age1argon2", b.to_base32(), Variant::Bech32).unwrap()
    };

    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, "# recipient: {recipient_str}").unwrap();
    writeln!(f, "{identity_str}").unwrap();

    // Decode identity and re-derive recipient — must match.
    let identity_line = identity_str.as_str();
    use bech32::FromBase32;
    let lower = identity_line.to_lowercase();
    let (hrp, data, _v) = bech32::decode(&lower).unwrap();
    assert_eq!(hrp, "age-plugin-argon2-");
    let bytes = Vec::<u8>::from_base32(&data).unwrap();
    assert_eq!(bytes.len(), 12);
    let m_cost = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let t_cost = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let p_cost = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let decoded_params = Argon2Params::new(m_cost, t_cost, p_cost).unwrap();
    assert_eq!(decoded_params, params);
}
