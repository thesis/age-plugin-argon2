use std::collections::{HashMap, HashSet};
use std::io;

use age::Identity;
use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    Callbacks, PluginHandler,
};
use age_plugin_argon2::{Argon2Params, Argon2idIdentity, Argon2idRecipient};
use secrecy::ExposeSecret;

use crate::encoding::{decode_identity, decode_recipient};

const STANZA_TAG: &str = "thesis.co/argon2";

pub struct RecipientPlugin {
    recipients: Vec<Argon2Params>,
    identities: Vec<Argon2Params>,
}

impl RecipientPlugin {
    pub fn new() -> Self {
        Self {
            recipients: Vec::new(),
            identities: Vec::new(),
        }
    }
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        let _ = plugin_name;
        // bytes is the raw decoded bech32 payload — re-encode so decode_recipient can parse it.
        // The age-plugin framework strips the HRP and passes only the raw data bytes.
        // We reconstruct params directly from the 12-byte payload.
        let params = params_from_plugin_bytes(bytes)
            .map_err(|e| recipient::Error::Recipient { index, message: e })?;
        self.recipients.push(params);
        Ok(())
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        let _ = plugin_name;
        let params = params_from_plugin_bytes(bytes)
            .map_err(|e| recipient::Error::Identity { index, message: e })?;
        self.identities.push(params);
        Ok(())
    }

    fn labels(&mut self) -> HashSet<String> {
        // No labels — stanzas from this plugin can be combined freely.
        HashSet::new()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        let passphrase = match callbacks.request_secret("Passphrase for age-plugin-argon2")? {
            Ok(p) => p,
            Err(_) => {
                return Ok(Err(vec![recipient::Error::Internal {
                    message: "passphrase request declined".to_string(),
                }]));
            }
        };
        let passphrase_bytes = passphrase.expose_secret().as_bytes().to_vec();

        let all_params: Vec<Argon2Params> = self
            .recipients
            .iter()
            .chain(self.identities.iter())
            .copied()
            .collect();

        let mut result = Vec::with_capacity(file_keys.len());
        for file_key in &file_keys {
            let mut stanzas = Vec::new();
            for &params in &all_params {
                let recipient = Argon2idRecipient::new(&passphrase_bytes, params);
                match age::Recipient::wrap_file_key(&recipient, file_key) {
                    Ok((s, _labels)) => stanzas.extend(s),
                    Err(e) => {
                        return Ok(Err(vec![recipient::Error::Internal {
                            message: e.to_string(),
                        }]));
                    }
                }
            }
            result.push(stanzas);
        }

        Ok(Ok(result))
    }
}

pub struct IdentityPlugin {
    identities: Vec<Argon2Params>,
}

impl IdentityPlugin {
    pub fn new() -> Self {
        Self {
            identities: Vec::new(),
        }
    }
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        let _ = plugin_name;
        let params = params_from_plugin_bytes(bytes)
            .map_err(|e| identity::Error::Identity { index, message: e })?;
        self.identities.push(params);
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        use age::DecryptError;

        let mut file_keys: HashMap<usize, Result<FileKey, Vec<identity::Error>>> = HashMap::new();

        // Collect file indices that have at least one matching stanza.
        let matching: Vec<usize> = files
            .iter()
            .enumerate()
            .filter(|(_i, stanzas)| stanzas.iter().any(|s| s.tag == STANZA_TAG))
            .map(|(i, _)| i)
            .collect();

        if matching.is_empty() {
            return Ok(file_keys);
        }

        // Prompt once for the passphrase.
        let passphrase = match callbacks.request_secret("Passphrase for age-plugin-argon2")? {
            Ok(p) => p,
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
            }
        };
        let passphrase_bytes = passphrase.expose_secret().as_bytes().to_vec();

        for file_index in matching {
            let stanzas = &files[file_index];
            let our_stanzas: Vec<&Stanza> =
                stanzas.iter().filter(|s| s.tag == STANZA_TAG).collect();

            let identity = Argon2idIdentity::new(&passphrase_bytes);
            for stanza in our_stanzas {
                match identity.unwrap_stanza(stanza) {
                    Some(Ok(fk)) => {
                        file_keys.insert(file_index, Ok(fk));
                        break;
                    }
                    Some(Err(DecryptError::KeyDecryptionFailed)) => {
                        file_keys.insert(
                            file_index,
                            Err(vec![identity::Error::Identity {
                                index: 0,
                                message: "incorrect passphrase".to_string(),
                            }]),
                        );
                        break;
                    }
                    Some(Err(e)) => {
                        file_keys.insert(
                            file_index,
                            Err(vec![identity::Error::Internal {
                                message: e.to_string(),
                            }]),
                        );
                        break;
                    }
                    None => continue,
                }
            }
        }

        Ok(file_keys)
    }
}

pub struct Argon2PluginHandler;

impl PluginHandler for Argon2PluginHandler {
    type RecipientV1 = RecipientPlugin;
    type IdentityV1 = IdentityPlugin;

    fn recipient_v1(self) -> io::Result<RecipientPlugin> {
        Ok(RecipientPlugin::new())
    }

    fn identity_v1(self) -> io::Result<IdentityPlugin> {
        Ok(IdentityPlugin::new())
    }
}

/// Decode Argon2 params from the 12-byte raw payload passed by age-plugin framework.
///
/// The framework decodes the bech32 payload and passes raw bytes, so we parse directly.
fn params_from_plugin_bytes(bytes: &[u8]) -> Result<Argon2Params, String> {
    if bytes.len() != 12 {
        // Might be a full bech32 string (e.g. when used from tests).
        // Try interpreting as UTF-8 recipient/identity string first.
        if let Ok(s) = std::str::from_utf8(bytes) {
            if let Ok(p) = decode_recipient(s) {
                return Ok(p);
            }
            if let Ok(p) = decode_identity(s) {
                return Ok(p);
            }
        }
        return Err(format!("expected 12-byte payload, got {}", bytes.len()));
    }
    let m_cost = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let t_cost = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let p_cost = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    Argon2Params::new(m_cost, t_cost, p_cost).map_err(|e| e.to_string())
}
