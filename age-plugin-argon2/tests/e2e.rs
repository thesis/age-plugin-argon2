#![cfg(unix)]
/// End-to-end tests using rage and passage as the age client.
///
/// These tests verify the full IPC state machine: our binary is discovered via PATH,
/// speaks the age-plugin protocol, and interoperates with real age clients.
///
/// Both `rage` and `passage` must be installed and in PATH. If they are not, the tests
/// fail with an actionable message rather than silently skipping.
///
/// KDF params are set to the minimum valid values (m=8, t=1, p=1) so the tests run fast.
///
/// # Passphrase injection
///
/// rage discovers pinentry via PATH and speaks the Assuan protocol to get passphrases.
/// We place a custom `pinentry` shim first in PATH that returns `PINENTRY_PASSPHRASE`
/// from the environment. This avoids PTY interaction for rage entirely.
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rexpect::session::spawn_command;
use tempfile::TempDir;

// Minimum valid Argon2 params — fast enough for tests.
const M_COST: &str = "8";
const T_COST: &str = "1";
const P_COST: &str = "1";

const PASSPHRASE: &str = "e2e-test-passphrase";

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

fn plugin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_age-plugin-argon2")
}

fn require_tool(name: &str) {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|_| {
            panic!(
                "`{name}` not found in PATH — install it before running e2e tests\n\
                 See .github/workflows/ci.yml for how CI installs these tools."
            )
        });
}

/// Write a `pinentry` shim to `dir/pinentry` that speaks the Assuan protocol
/// and returns `$PINENTRY_PASSPHRASE` in response to `GETPIN`.
///
/// rage discovers pinentry via PATH, so prepending `dir` to PATH causes rage
/// (and any subprocess it spawns) to use this shim instead of pinentry-curses.
fn write_pinentry(dir: &Path) {
    let script = "\
#!/bin/sh
printf 'OK Pleased to meet you\\n'
while IFS= read -r line; do
    line=$(printf '%s' \"$line\" | tr -d '\\r')
    case \"$line\" in
        GETPIN*) printf 'D %s\\nOK\\n' \"$PINENTRY_PASSPHRASE\" ;;
        BYE*)    printf 'OK\\n'; exit 0 ;;
        *)       printf 'OK\\n' ;;
    esac
done
";
    for name in &["pinentry", "pinentry-curses", "pinentry-tty"] {
        let path = dir.join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Returns a PATH string with the pinentry dir and plugin binary dir prepended.
fn make_path(pinentry_dir: &Path) -> String {
    let bin_dir = Path::new(plugin_bin())
        .parent()
        .expect("plugin binary has no parent dir");
    let existing = std::env::var("PATH").unwrap_or_default();
    format!(
        "{}:{}:{existing}",
        pinentry_dir.display(),
        bin_dir.display()
    )
}

/// Generate an identity file and return (identity_path, recipient_string).
fn generate_identity(dir: &Path) -> (PathBuf, String) {
    let identity_path = dir.join("identity.txt");

    let status = Command::new(plugin_bin())
        .args([
            "--generate",
            "--m-cost",
            M_COST,
            "--t-cost",
            T_COST,
            "--p-cost",
            P_COST,
            "-o",
        ])
        .arg(&identity_path)
        .status()
        .expect("failed to run age-plugin-argon2 --generate");
    assert!(status.success(), "--generate exited with failure");

    let output = Command::new(plugin_bin())
        .args(["--list", "-i"])
        .arg(&identity_path)
        .output()
        .expect("failed to run age-plugin-argon2 --list");
    assert!(output.status.success(), "--list exited with failure");

    let recipient = String::from_utf8(output.stdout)
        .expect("--list output is not UTF-8")
        .trim()
        .to_string();
    assert!(!recipient.is_empty(), "--list produced no output");

    (identity_path, recipient)
}

// ------------------------------------------------------------------
// rage tests
// ------------------------------------------------------------------

/// rage encrypt → rage decrypt roundtrip.
///
/// Passphrase is provided via the pinentry shim — no PTY needed.
#[test]
fn rage_encrypt_decrypt_roundtrip() {
    require_tool("rage");

    let dir = TempDir::new().unwrap();
    let pinentry_dir = TempDir::new().unwrap();
    write_pinentry(pinentry_dir.path());
    let (identity_path, recipient) = generate_identity(dir.path());

    let plaintext_path = dir.path().join("plain.txt");
    let ciphertext_path = dir.path().join("cipher.age");
    let decrypted_path = dir.path().join("decrypted.txt");
    let plaintext = "hello from rage e2e test\n";
    let path = make_path(pinentry_dir.path());

    std::fs::write(&plaintext_path, plaintext).unwrap();

    let enc = Command::new("rage")
        .args(["-r", &recipient, "-o"])
        .arg(&ciphertext_path)
        .arg(&plaintext_path)
        .env("PATH", &path)
        .env("PINENTRY_PASSPHRASE", PASSPHRASE)
        .output()
        .expect("failed to run rage encrypt");
    assert!(
        enc.status.success(),
        "rage encrypt failed:\n{}",
        String::from_utf8_lossy(&enc.stderr),
    );

    let dec = Command::new("rage")
        .args(["-d", "-i"])
        .arg(&identity_path)
        .arg("-o")
        .arg(&decrypted_path)
        .arg(&ciphertext_path)
        .env("PATH", &path)
        .env("PINENTRY_PASSPHRASE", PASSPHRASE)
        .output()
        .expect("failed to run rage decrypt");
    assert!(
        dec.status.success(),
        "rage decrypt failed:\n{}",
        String::from_utf8_lossy(&dec.stderr),
    );

    assert_eq!(std::fs::read_to_string(&decrypted_path).unwrap(), plaintext);
}

/// Wrong passphrase: rage decrypt should exit non-zero.
#[test]
fn rage_wrong_passphrase_fails() {
    require_tool("rage");

    let dir = TempDir::new().unwrap();
    let pinentry_dir = TempDir::new().unwrap();
    write_pinentry(pinentry_dir.path());
    let (identity_path, recipient) = generate_identity(dir.path());

    let plaintext_path = dir.path().join("plain.txt");
    let ciphertext_path = dir.path().join("cipher.age");
    let path = make_path(pinentry_dir.path());

    std::fs::write(&plaintext_path, b"secret").unwrap();

    let enc = Command::new("rage")
        .args(["-r", &recipient, "-o"])
        .arg(&ciphertext_path)
        .arg(&plaintext_path)
        .env("PATH", &path)
        .env("PINENTRY_PASSPHRASE", PASSPHRASE)
        .output()
        .unwrap();
    assert!(enc.status.success(), "rage encrypt failed");

    let dec = Command::new("rage")
        .args(["-d", "-i"])
        .arg(&identity_path)
        .arg(&ciphertext_path)
        .env("PATH", &path)
        .env("PINENTRY_PASSPHRASE", "wrong-passphrase")
        .output()
        .unwrap();

    assert!(
        !dec.status.success(),
        "rage decrypt should have failed with wrong passphrase"
    );
}

// ------------------------------------------------------------------
// passage tests
// ------------------------------------------------------------------

/// passage insert → passage show roundtrip.
///
/// The passage store is set up manually (no `passage init`) since the
/// installed version may not have that subcommand. The argon2 passphrase
/// is provided via the pinentry shim; PTY is only needed for passage's
/// own bash `read` prompts when inserting.
#[test]
fn passage_insert_show_roundtrip() {
    require_tool("rage");
    require_tool("passage");

    let store_dir = TempDir::new().unwrap();
    let identity_dir = TempDir::new().unwrap();
    let pinentry_dir = TempDir::new().unwrap();
    write_pinentry(pinentry_dir.path());

    let (identity_path, recipient) = generate_identity(identity_dir.path());
    let path = make_path(pinentry_dir.path());

    // Set up the passage store manually: create the directory and write the
    // recipients file. This avoids relying on `passage init`.
    std::fs::create_dir_all(store_dir.path()).unwrap();
    std::fs::write(
        store_dir.path().join(".age-recipients"),
        format!("{recipient}\n"),
    )
    .unwrap();

    let secret_name = "test/my-secret";
    let secret_value = "hunter2-from-passage-e2e";

    // Insert: passage uses bash `read -s -p` to get the password, which goes
    // through the PTY. rage gets the argon2 passphrase from the pinentry shim.
    // We handle both "Enter password" and "Retype password" prompts.
    let mut cmd = Command::new("passage");
    cmd.args(["insert", secret_name])
        .env("PASSWORD_STORE_DIR", store_dir.path())
        .env("PASSAGE_IDENTITIES_FILE", &identity_path)
        .env("PASSAGE_AGE", "rage")
        .env("PATH", &path)
        .env("PINENTRY_PASSPHRASE", PASSPHRASE);
    let mut ins = spawn_command(cmd, Some(30_000)).expect("failed to spawn passage insert");

    ins.exp_regex("(?i)enter password")
        .expect("no 'Enter password' prompt from passage");
    ins.send_line(secret_value).unwrap();
    ins.exp_regex("(?i)retype password")
        .expect("no 'Retype password' prompt from passage");
    ins.send_line(secret_value).unwrap();
    ins.exp_eof().expect("passage insert did not exit cleanly");

    // Show: passage calls rage which uses the pinentry shim — no PTY needed.
    let show = Command::new("passage")
        .args(["show", secret_name])
        .env("PASSWORD_STORE_DIR", store_dir.path())
        .env("PASSAGE_IDENTITIES_FILE", &identity_path)
        .env("PASSAGE_AGE", "rage")
        .env("PATH", &path)
        .env("PINENTRY_PASSPHRASE", PASSPHRASE)
        .output()
        .expect("failed to run passage show");

    assert!(
        show.status.success(),
        "passage show failed:\n{}",
        String::from_utf8_lossy(&show.stderr),
    );
    let output = String::from_utf8_lossy(&show.stdout);
    assert!(
        output.contains(secret_value),
        "passage show output did not contain the secret; got: {output:?}",
    );
}
