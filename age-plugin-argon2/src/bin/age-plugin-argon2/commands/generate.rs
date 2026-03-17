use std::fs;
use std::io::{self, Write};
use std::path::Path;

use age_plugin_argon2::Argon2Params;

use crate::encoding::{encode_identity, encode_recipient};

pub fn run(
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let params = Argon2Params::new(m_cost, t_cost, p_cost)?;
    let recipient = encode_recipient(&params);
    let identity = encode_identity(&params);

    let now = chrono_now();
    let contents = format!(
        "# created: {}\n# recipient: {}\n{}\n",
        now, recipient, identity
    );

    match output {
        Some(path) => {
            fs::write(path, &contents)?;
            eprintln!("recipient: {recipient}");
            eprintln!("Identity file written to {}", path.display());
        }
        None => {
            io::stdout().write_all(contents.as_bytes())?;
            eprintln!("recipient: {recipient}");
        }
    }

    Ok(())
}

fn chrono_now() -> String {
    // Use a simple approach without pulling in chrono.
    // std::time::SystemTime gives seconds since UNIX epoch.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Format as a fixed-format UTC date — good enough for an age identity comment.
    let (y, mo, d, h, min, s) = unix_to_ymd_hms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{min:02}:{s:02}Z")
}

fn unix_to_ymd_hms(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = secs % 60;
    let min = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    // Gregorian calendar computation.
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };

    (y, mo, d, h, min, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn generate_writes_identity_file() {
        let f = NamedTempFile::new().unwrap();
        run(65536, 3, 4, Some(f.path())).unwrap();

        let contents = std::fs::read_to_string(f.path()).unwrap();
        assert!(contents.contains("# created:"));
        assert!(contents.contains("# recipient: age1argon2"));
        assert!(contents.contains("AGE-PLUGIN-ARGON2-"));
    }

    #[test]
    fn generate_stdout_when_no_output() {
        // Just verify it doesn't error.
        run(65536, 3, 4, None).unwrap();
    }

    #[test]
    fn generate_roundtrip_params() {
        use crate::encoding::{decode_identity, decode_recipient};

        let f = NamedTempFile::new().unwrap();
        run(131072, 2, 2, Some(f.path())).unwrap();

        let contents = std::fs::read_to_string(f.path()).unwrap();
        let recipient_line = contents
            .lines()
            .find(|l| l.starts_with("# recipient:"))
            .unwrap();
        let recipient_str = recipient_line.trim_start_matches("# recipient: ");
        let params_r = decode_recipient(recipient_str).unwrap();
        assert_eq!(params_r.m_cost(), 131072);
        assert_eq!(params_r.t_cost(), 2);
        assert_eq!(params_r.p_cost(), 2);

        let identity_line = contents
            .lines()
            .find(|l| l.starts_with("AGE-PLUGIN-"))
            .unwrap();
        let params_i = decode_identity(identity_line).unwrap();
        assert_eq!(params_i, params_r);
    }
}
