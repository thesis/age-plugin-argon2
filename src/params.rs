/// Argon2id parameters for key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB
    pub m_cost: u32,
    /// Time cost (iterations)
    pub t_cost: u32,
    /// Parallelism
    pub p_cost: u32,
}

/// Default: m=65536 (64 MiB), t=3, p=4 (matching KDBX4 settings)
impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}
