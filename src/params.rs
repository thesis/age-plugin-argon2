use std::fmt;

/// Argon2id parameters for key derivation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB (minimum 8)
    m_cost: u32,
    /// Time cost / iterations (minimum 1)
    t_cost: u32,
    /// Parallelism (minimum 1)
    p_cost: u32,
}

/// Parameter validation error.
#[derive(Debug, thiserror::Error)]
#[error("invalid Argon2 parameters: {reason}")]
pub struct InvalidParams {
    reason: String,
}

impl Argon2Params {
    /// Create validated Argon2id parameters.
    ///
    /// Validates against argon2 library minimums:
    /// - `m_cost` >= 8 KiB (argon2 crate minimum)
    /// - `t_cost` >= 1
    /// - `p_cost` >= 1
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self, InvalidParams> {
        // Validate by attempting to build argon2::Params — this catches all
        // constraints enforced by the library (including m_cost >= 8*p_cost).
        argon2::Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(|e| InvalidParams {
            reason: e.to_string(),
        })?;

        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
        })
    }

    pub fn m_cost(&self) -> u32 {
        self.m_cost
    }

    pub fn t_cost(&self) -> u32 {
        self.t_cost
    }

    pub fn p_cost(&self) -> u32 {
        self.p_cost
    }
}

impl fmt::Debug for Argon2Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Argon2Params")
            .field("m_cost", &self.m_cost)
            .field("t_cost", &self.t_cost)
            .field("p_cost", &self.p_cost)
            .finish()
    }
}

/// Default: m=65536 (64 MiB), t=3, p=4 (matching KDBX4 settings)
impl Default for Argon2Params {
    fn default() -> Self {
        // These are known-valid constants.
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_params_are_valid() {
        let p = Argon2Params::default();
        assert_eq!(p.m_cost(), 65536);
        assert_eq!(p.t_cost(), 3);
        assert_eq!(p.p_cost(), 4);
    }

    #[test]
    fn test_valid_params() {
        let p = Argon2Params::new(256, 1, 1).unwrap();
        assert_eq!(p.m_cost(), 256);
    }

    #[test]
    fn test_zero_t_cost_rejected() {
        assert!(Argon2Params::new(256, 0, 1).is_err());
    }

    #[test]
    fn test_zero_p_cost_rejected() {
        assert!(Argon2Params::new(256, 1, 0).is_err());
    }

    #[test]
    fn test_m_cost_too_low_rejected() {
        // m_cost must be >= 8 * p_cost
        assert!(Argon2Params::new(1, 1, 1).is_err());
    }
}
