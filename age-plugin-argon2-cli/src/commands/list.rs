use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::encoding::{decode_identity, encode_recipient};

pub fn run(identity_file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(identity_file)?;
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("AGE-PLUGIN-ARGON2-") {
            match decode_identity(trimmed) {
                Ok(params) => {
                    let recipient = encode_recipient(&params);
                    writeln!(out, "{recipient}")?;
                }
                Err(e) => {
                    eprintln!("warning: skipping invalid identity line: {e}");
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{encode_identity, encode_recipient};
    use age_plugin_argon2::Argon2Params;
    use tempfile::NamedTempFile;

    #[test]
    fn list_identity_file() {
        let params = Argon2Params::default();
        let identity = encode_identity(&params);
        let recipient = encode_recipient(&params);

        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# created: 2026-01-01T00:00:00Z").unwrap();
        writeln!(f, "# recipient: {recipient}").unwrap();
        writeln!(f, "{identity}").unwrap();
        use std::io::Write;

        // We can't easily capture stdout here, so just confirm it doesn't error.
        run(f.path()).unwrap();
    }

    #[test]
    fn list_skips_comment_lines() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(f, "# this is a comment").unwrap();
        writeln!(f, "# recipient: age1argon2somethinghere").unwrap();
        run(f.path()).unwrap();
    }

    #[test]
    fn list_multiple_identities() {
        let p1 = Argon2Params::new(65536, 3, 4).unwrap();
        let p2 = Argon2Params::new(131072, 2, 2).unwrap();

        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(f, "{}", encode_identity(&p1)).unwrap();
        writeln!(f, "{}", encode_identity(&p2)).unwrap();

        run(f.path()).unwrap();
    }
}
