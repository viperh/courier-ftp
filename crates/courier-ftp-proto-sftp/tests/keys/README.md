# SSH key-format fixtures — TEST-ONLY

> **WARNING: TEST-ONLY key material, committed on purpose.** These keys protect
> nothing. Never trust them anywhere outside the courier-ftp tests. Secret scanners
> skip this directory.

They are the T76 sshd fixture keys (`tests/fixtures/sshd/keys/`, whose public keys are
in that image's `authorized_keys`) re-encoded in every format `keys::decode` reads,
written by `derive.py` (run it from the repository root; needs Python `cryptography`):

| File | Format |
|---|---|
| `id_ed25519`, `id_ecdsa_p256`, `id_rsa4096` | OpenSSH, unencrypted |
| `id_ed25519_enc` | OpenSSH, bcrypt + AES (passphrase `fixture`) |
| `id_rsa_pkcs1.pem` / `id_rsa_pkcs1_enc.pem` | PEM PKCS#1 RSA, plain / legacy AES-256-CBC |
| `id_ec_sec1.pem` | PEM SEC1 EC (P-256) |
| `id_ed25519_pkcs8.pem` | PKCS#8 |
| `id_rsa_pkcs8_enc.pem` | encrypted PKCS#8 (PBES2) |
| `id_ed25519.ppk`, `id_ed25519_v3.ppk` | PuTTY v2 / v3, unencrypted |
| `id_rsa_v2_enc.ppk` | PuTTY v2, AES-256-CBC |
| `id_ecdsa_v3_enc.ppk` | PuTTY v3, Argon2id + AES-256-CBC |
| `unsupported_*` | DSA and RSA-1024 keys that must be refused |

Encrypted fixtures use the passphrase `fixture`. `fingerprints.txt` lists each fixture's
expected `SHA256:` fingerprint (`keys::tests::decode_every_fixture_matches_fingerprint`).
