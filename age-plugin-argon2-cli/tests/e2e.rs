/// End-to-end tests using rage and passage as the age client.
///
/// These tests verify the full IPC state machine: our binary is discovered via PATH,
/// speaks the age-plugin protocol, and interoperates with real age clients.
///
/// Both `rage` and `passage` must be installed and in PATH. If they are not, the tests
/// fail with an actionable message rather than silently skipping.
///
/// KDF params are set to the minimum valid values (m=8, t=1, p=1) so the tests run fast.
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

/// Returns a PATH string that prepends the directory containing our plugin binary.
fn path_with_plugin() -> String {
    let bin_dir = Path::new(plugin_bin())
        .parent()
        .expect("plugin binary has no parent dir");
    let existing = std::env::var("PATH").unwrap_or_default();
    format!("{}:{existing}", bin_dir.display())
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
#[test]
fn rage_encrypt_decrypt_roundtrip() {
    require_tool("rage");

    let dir = TempDir::new().unwrap();
    let (identity_path, recipient) = generate_identity(dir.path());

    let plaintext_path = dir.path().join("plain.txt");
    let ciphertext_path = dir.path().join("cipher.age");
    let decrypted_path = dir.path().join("decrypted.txt");
    let plaintext = "hello from rage e2e test\n";

    std::fs::write(&plaintext_path, plaintext).unwrap();

    // Encrypt — plugin prompts for passphrase via rage.
    let mut cmd = Command::new("rage");
    cmd.args(["-r", &recipient, "-o"])
        .arg(&ciphertext_path)
        .arg(&plaintext_path)
        .env("PATH", path_with_plugin());
    let mut enc = spawn_command(cmd, Some(10_000)).expect("failed to spawn rage for encryption");

    enc.exp_regex("(?i)passphrase")
        .expect("no passphrase prompt during encryption");
    enc.send_line(PASSPHRASE).unwrap();
    enc.exp_eof().expect("rage encrypt did not exit cleanly");

    assert!(ciphertext_path.exists(), "no ciphertext file produced");

    // Decrypt — plugin prompts for passphrase again.
    let mut cmd = Command::new("rage");
    cmd.args(["-d", "-i"])
        .arg(&identity_path)
        .arg("-o")
        .arg(&decrypted_path)
        .arg(&ciphertext_path)
        .env("PATH", path_with_plugin());
    let mut dec = spawn_command(cmd, Some(10_000)).expect("failed to spawn rage for decryption");

    dec.exp_regex("(?i)passphrase")
        .expect("no passphrase prompt during decryption");
    dec.send_line(PASSPHRASE).unwrap();
    dec.exp_eof().expect("rage decrypt did not exit cleanly");

    let decrypted = std::fs::read_to_string(&decrypted_path).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Wrong passphrase: rage decrypt should exit without producing the plaintext.
#[test]
fn rage_wrong_passphrase_fails() {
    require_tool("rage");

    let dir = TempDir::new().unwrap();
    let (identity_path, recipient) = generate_identity(dir.path());

    let plaintext_path = dir.path().join("plain.txt");
    let ciphertext_path = dir.path().join("cipher.age");
    std::fs::write(&plaintext_path, b"secret").unwrap();

    // Encrypt with the correct passphrase.
    let mut cmd = Command::new("rage");
    cmd.args(["-r", &recipient, "-o"])
        .arg(&ciphertext_path)
        .arg(&plaintext_path)
        .env("PATH", path_with_plugin());
    let mut enc = spawn_command(cmd, Some(10_000)).unwrap();
    enc.exp_regex("(?i)passphrase").unwrap();
    enc.send_line(PASSPHRASE).unwrap();
    enc.exp_eof().unwrap();

    // Decrypt with the wrong passphrase — should fail.
    let mut cmd = Command::new("rage");
    cmd.args(["-d", "-i"])
        .arg(&identity_path)
        .arg(&ciphertext_path)
        .env("PATH", path_with_plugin());
    let mut dec = spawn_command(cmd, Some(10_000)).unwrap();
    dec.exp_regex("(?i)passphrase").unwrap();
    dec.send_line("wrong-passphrase").unwrap();
    let remaining = dec.exp_eof().unwrap_or_default();

    assert!(
        !remaining.contains("secret"),
        "decryption should have failed"
    );
}

// ------------------------------------------------------------------
// passage tests
// ------------------------------------------------------------------

/// passage insert → passage show roundtrip.
///
/// passage init sets up the store with our recipient. insert encrypts the
/// secret (rage invokes our plugin for the passphrase). show decrypts it.
#[test]
fn passage_insert_show_roundtrip() {
    require_tool("rage");
    require_tool("passage");

    let store_dir = TempDir::new().unwrap();
    let identity_dir = TempDir::new().unwrap();
    let (identity_path, recipient) = generate_identity(identity_dir.path());

    let secret_name = "test/my-secret";
    let secret_value = "hunter2-from-passage-e2e";
    let path_env = path_with_plugin();

    // Init the passage store with our recipient.
    let status = Command::new("passage")
        .args(["init", &recipient])
        .env("PASSWORD_STORE_DIR", store_dir.path())
        .env("PASSAGE_IDENTITIES_FILE", &identity_path)
        .env("PASSAGE_AGE", "rage")
        .env("PATH", &path_env)
        .status()
        .expect("failed to run passage init");
    assert!(status.success(), "passage init failed");

    // Insert: passage prompts for the password, then rage invokes our plugin.
    // -f skips the retype confirmation prompt.
    let mut cmd = Command::new("passage");
    cmd.args(["insert", "-f", secret_name])
        .env("PASSWORD_STORE_DIR", store_dir.path())
        .env("PASSAGE_IDENTITIES_FILE", &identity_path)
        .env("PASSAGE_AGE", "rage")
        .env("PATH", &path_env);
    let mut ins = spawn_command(cmd, Some(30_000)).expect("failed to spawn passage insert");

    ins.exp_regex("(?i)enter password")
        .expect("no password prompt from passage insert");
    ins.send_line(secret_value).unwrap();

    ins.exp_regex("(?i)passphrase")
        .expect("no passphrase prompt from plugin during insert");
    ins.send_line(PASSPHRASE).unwrap();

    ins.exp_eof().expect("passage insert did not exit cleanly");

    // Show: rage invokes our plugin for the passphrase, then passage prints the secret.
    let mut cmd = Command::new("passage");
    cmd.args(["show", secret_name])
        .env("PASSWORD_STORE_DIR", store_dir.path())
        .env("PASSAGE_IDENTITIES_FILE", &identity_path)
        .env("PASSAGE_AGE", "rage")
        .env("PATH", &path_env);
    let mut show = spawn_command(cmd, Some(30_000)).expect("failed to spawn passage show");

    show.exp_regex("(?i)passphrase")
        .expect("no passphrase prompt from plugin during show");
    show.send_line(PASSPHRASE).unwrap();

    let output = show.exp_eof().expect("passage show did not exit cleanly");
    assert!(
        output.contains(secret_value),
        "passage show output did not contain the secret; got: {output:?}"
    );
}
