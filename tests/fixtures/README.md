# e2e fixtures (T76)

| Directory | What |
|---|---|
| `sshd/` | OpenSSH (SFTP) image: profiles, TEST-ONLY client keys, PAM OTP module |
| `ftpd/` | vsftpd / proftpd / pure-ftpd image: profiles, certificate variants |
| `proxy/` | squid (HTTP CONNECT) and dante (SOCKS 4/5) image |
| `tls/` | the TEST-ONLY CA that signs the ftpd certificates |
| `editor/` | `fake-editor.sh` for the edit round trip |

Images are built by the harness (`crates/courier-ftp-e2e`, tag = hash of the
directory) or by CI (`COURIER_E2E_*_IMAGE`). Base images come from
`public.ecr.aws/docker/library/` (the ECR mirror of the Docker official images) to
avoid Docker Hub's anonymous pull limit. Every key directory has a README saying the
material is TEST-ONLY.
