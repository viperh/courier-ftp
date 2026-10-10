# OpenSSH (SFTP) e2e fixture (T76)

> **WARNING: everything under `keys/` is TEST-ONLY key material.** The private keys
> are committed to a public repository and protect nothing. Never add them to an
> agent, an `authorized_keys` or a `known_hosts` outside these test containers.
> Secret scanners skip this directory.

One Docker image (`Dockerfile`, Debian bookworm-slim from the ECR mirror of the Docker
official images) with OpenSSH and python3. The sshd configuration is picked at
container start with `SSHD_PROFILE=<profile>`; the harness in `crates/courier-ftp-e2e`
(`Sshd::start(SshdProfile::…)`) does that for you. The entrypoint also accepts
`--list` (print the profiles) and `--check` (validate one without serving; unknown
profile → exit 64).

## Users

| User | Password | Keys | Directories |
|---|---|---|---|
| `test` | `test` | `keys/authorized_keys` | `~/upload/` (writable), `~/fixtures/` |
| `canary` | `CANARY-PW-e2e-7f3a` | same | same |

`~/fixtures/` is the `FIXTURE_TREE` of `crates/courier-ftp-e2e/src/files.rs`, generated
at image build by `bin/make-fixture-tree` (same algorithm as `files::fixture_bytes`).
The same layout exists inside the chroots `/srv/chroot/home/<user>` and
`/srv/win/C:/Users/<user>`.

## Profiles (`profiles/<name>.conf`)

`sshd_config` includes the profile first; for most keywords sshd keeps the first value,
so a profile overrides the base. Profiles must not use `Match`.

| Profile | Essentials |
|---|---|
| `password` | `PasswordAuthentication yes`, `Subsystem sftp internal-sftp` |
| `key` | public keys only |
| `kbd` | keyboard-interactive via PAM: `Password: ` (pam_unix), then `Verification code: ` (`pam/pam_courier_otp.c`, code `424242`) |
| `maxauth2` | `MaxAuthTries 2`, keys only |
| `legacy` | `diffie-hellman-group14-sha1`, `ssh-rsa`, `aes128-cbc`, `hmac-sha1` only |
| `chroot-sftp` | `ForceCommand internal-sftp`, `ChrootDirectory /srv/chroot` |
| `windows-like` | `ChrootDirectory /srv/win`, `ForceCommand internal-sftp -d /C:/Users/%u` |
| `maxsessions1` | `MaxSessions 1` |
| `maxconn1` | sshd on 127.0.0.1:2222 behind `bin/conn-limit-proxy` on :22 (one TCP connection at a time) |

Host keys are generated per container on first start; `courier-regen-hostkeys`
replaces them and makes sshd re-execute (`Sshd::regenerate_host_key`). sshd logs at
`DEBUG1` to stderr, which the harness dumps when a test fails.

## Keys (`keys/`)

See `keys/README.md`.

## Checking without Docker

`./check-configs.sh` runs the local `sshd -t` over the base config with every profile.
`cargo test -p courier-ftp-e2e --test fixtures` runs it when `sshd` is installed.
