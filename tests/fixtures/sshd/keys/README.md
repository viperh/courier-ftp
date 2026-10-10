# SSH fixture keys — TEST-ONLY

> **WARNING: TEST-ONLY key material, committed on purpose.** These keys protect
> nothing. Never trust them anywhere outside the courier-ftp e2e containers. Secret
> scanners skip this directory.

| File | What |
|---|---|
| `id_ed25519`, `id_ecdsa` (P-256), `id_rsa` (4096) | OpenSSH private keys, unencrypted, authorized |
| `id_ed25519_encrypted` | OpenSSH private key, passphrase `fixture`, authorized |
| `id_ed25519.ppk` | PuTTY v2, unencrypted (the `id_ed25519` key) |
| `id_ed25519_v3.ppk` | PuTTY v3, unencrypted (the `id_ed25519` key) |
| `id_ed25519_v3_encrypted.ppk` | PuTTY v3, Argon2id + AES-256-CBC, passphrase `fixture` (the `id_ed25519` key) |
| `*.pub` | public keys, comment `courier-ftp-e2e-fixture-TEST-ONLY` |
| `authorized_keys` | the ed25519, ecdsa, rsa and encrypted public keys |

Regenerate with `python3 generate.py` in this directory (needs `cryptography` and
`bcrypt`). Equivalent commands with the OpenSSH and PuTTY tools:

```sh
C=courier-ftp-e2e-fixture-TEST-ONLY
ssh-keygen -t ed25519 -N '' -C "$C" -f id_ed25519
ssh-keygen -t ecdsa -b 256 -N '' -C "$C" -f id_ecdsa
ssh-keygen -t rsa -b 4096 -N '' -C "$C" -f id_rsa
ssh-keygen -t ed25519 -N fixture -C "$C-encrypted" -f id_ed25519_encrypted
puttygen id_ed25519 -O private --ppk-param version=2 -o id_ed25519.ppk
puttygen id_ed25519 -O private --ppk-param version=3 -o id_ed25519_v3.ppk
puttygen id_ed25519 -O private --ppk-param version=3 --new-passphrase <(echo fixture) \
    -o id_ed25519_v3_encrypted.ppk
cat id_ed25519.pub id_ecdsa.pub id_rsa.pub id_ed25519_encrypted.pub > authorized_keys
```

`cargo test -p courier-ftp-e2e --test fixtures` parses every key with the `ssh-key`
crate the client uses.
