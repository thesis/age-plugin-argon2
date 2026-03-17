# age-plugin-argon2

An [age](https://age-encryption.org/) plugin that encrypts file keys using
[Argon2id](https://en.wikipedia.org/wiki/Argon2) — a memory-hard password
hashing function. Recipients encode the KDF parameters directly, so any
compatible age client can derive the file key from a passphrase without a
separate config file.

The plugin implements the age IPC plugin protocol and works with any
age-compatible client: [rage](https://github.com/str4d/rage),
[passage](https://github.com/FiloSottile/passage), and others.

## Why Argon2id?

age ships built-in passphrase encryption using
[scrypt](https://en.wikipedia.org/wiki/Scrypt). Argon2id is an alternative KDF
with a few practical advantages:

- **Harder to crack in parallel.** Each Argon2id instance must hold the full
  memory cost in RAM simultaneously. Parallelising a brute-force attack requires
  proportionally more memory per thread, which raises the cost of GPU and ASIC
  cracking — important when ciphertext is publicly accessible.
- **Three tunable axes.** Memory cost (`--m-cost`), time cost (`--t-cost`), and
  parallelism (`--p-cost`) are independently configurable, so you can fit
  hardness to your hardware.
- **PHC winner.** Argon2id won the
  [Password Hashing Competition](https://www.password-hashing.net/) in 2015 and
  is the recommended choice for new systems (RFC 9106).
- **Encoded in the recipient.** Parameters travel with the ciphertext — no side
  channel needed to share KDF settings.

## Installation

```
cargo install age-plugin-argon2
```

The binary must be named `age-plugin-argon2` and be on your `$PATH` so age
clients can discover it automatically.

## Usage

### Generate an identity

```
age-plugin-argon2 --generate [-o OUTPUT] [--m-cost KiB] [--t-cost N] [--p-cost N]
```

Defaults: `--m-cost 65536` (64 MiB), `--t-cost 3`, `--p-cost 4`.

The identity is written to `OUTPUT` (or stdout). The corresponding recipient is
printed to stderr.

```
$ age-plugin-argon2 --generate -o key.txt
# Recipient: age1argon2...
```

### Encrypt

Pass the recipient string directly with `-r`, or point at an identity file with
`-R`:

```
rage -r age1argon2... -o secret.age plaintext.txt
rage -R key.txt -o secret.age plaintext.txt
```

The age client will prompt for a passphrase.

### Decrypt

```
rage -d -i key.txt -o plaintext.txt secret.age
```

The age client discovers the plugin via `$PATH`, handles the passphrase prompt,
and calls back into the plugin to unwrap the file key.

### List recipients

Extract the recipient strings from an identity file:

```
age-plugin-argon2 --list -i key.txt
```

## License

Licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your
option.
