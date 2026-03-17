use age_plugin_argon2::Argon2Params;
use bech32::{FromBase32, ToBase32, Variant};

pub const RECIPIENT_HRP: &str = "age1argon2";
pub const IDENTITY_HRP: &str = "age-plugin-argon2-";

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("bech32 decode failed: {0}")]
    Bech32(#[from] bech32::Error),
    #[error("wrong HRP: expected {expected}, got {got}")]
    WrongHrp { expected: String, got: String },
    #[error("wrong data length: expected 12 bytes, got {0}")]
    WrongLength(usize),
    #[error("invalid Argon2 parameters: {0}")]
    InvalidParams(#[from] age_plugin_argon2::InvalidParams),
}

fn params_to_bytes(params: &Argon2Params) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&params.m_cost().to_le_bytes());
    b[4..8].copy_from_slice(&params.t_cost().to_le_bytes());
    b[8..12].copy_from_slice(&params.p_cost().to_le_bytes());
    b
}

fn params_from_bytes(b: &[u8]) -> Result<Argon2Params, DecodeError> {
    if b.len() != 12 {
        return Err(DecodeError::WrongLength(b.len()));
    }
    let m_cost = u32::from_le_bytes(b[0..4].try_into().unwrap());
    let t_cost = u32::from_le_bytes(b[4..8].try_into().unwrap());
    let p_cost = u32::from_le_bytes(b[8..12].try_into().unwrap());
    Ok(Argon2Params::new(m_cost, t_cost, p_cost)?)
}

pub fn encode_recipient(params: &Argon2Params) -> String {
    let bytes = params_to_bytes(params);
    bech32::encode(RECIPIENT_HRP, bytes.to_base32(), Variant::Bech32)
        .expect("recipient HRP is valid")
}

pub fn decode_recipient(s: &str) -> Result<Argon2Params, DecodeError> {
    let (hrp, data, _variant) = bech32::decode(s)?;
    if hrp != RECIPIENT_HRP {
        return Err(DecodeError::WrongHrp {
            expected: RECIPIENT_HRP.to_string(),
            got: hrp,
        });
    }
    let bytes = Vec::<u8>::from_base32(&data)?;
    params_from_bytes(&bytes)
}

pub fn encode_identity(params: &Argon2Params) -> String {
    let bytes = params_to_bytes(params);
    bech32::encode(IDENTITY_HRP, bytes.to_base32(), Variant::Bech32)
        .expect("identity HRP is valid")
        .to_uppercase()
}

pub fn decode_identity(s: &str) -> Result<Argon2Params, DecodeError> {
    let lower = s.to_lowercase();
    let (hrp, data, _variant) = bech32::decode(&lower)?;
    if hrp != IDENTITY_HRP {
        return Err(DecodeError::WrongHrp {
            expected: IDENTITY_HRP.to_string(),
            got: hrp,
        });
    }
    let bytes = Vec::<u8>::from_base32(&data)?;
    params_from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_recipient_default() {
        let params = Argon2Params::default();
        let encoded = encode_recipient(&params);
        assert!(encoded.starts_with("age1argon2"));
        let decoded = decode_recipient(&encoded).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn roundtrip_identity_default() {
        let params = Argon2Params::default();
        let encoded = encode_identity(&params);
        assert!(encoded.starts_with("AGE-PLUGIN-ARGON2-"));
        let decoded = decode_identity(&encoded).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn roundtrip_recipient_min_params() {
        let params = Argon2Params::new(8, 1, 1).unwrap();
        let decoded = decode_recipient(&encode_recipient(&params)).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn roundtrip_identity_min_params() {
        let params = Argon2Params::new(8, 1, 1).unwrap();
        let decoded = decode_identity(&encode_identity(&params)).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn wrong_hrp_error() {
        let params = Argon2Params::default();
        let recipient = encode_recipient(&params);
        let err = decode_identity(&recipient).unwrap_err();
        assert!(matches!(err, DecodeError::WrongHrp { .. }));
    }

    #[test]
    fn malformed_input_error() {
        assert!(decode_recipient("not-bech32!!!").is_err());
    }

    #[test]
    fn wrong_length_error() {
        // Encode 8 bytes under the recipient HRP — valid bech32 but wrong payload size.
        let short = bech32::encode(RECIPIENT_HRP, [0u8; 8].to_base32(), Variant::Bech32).unwrap();
        let err = decode_recipient(&short).unwrap_err();
        assert!(matches!(err, DecodeError::WrongLength(_)));
    }
}
