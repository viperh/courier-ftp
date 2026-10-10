# FTP/FTPS e2e fixture (T76)

> `tls/` is a copy of the TEST-ONLY CA in `tests/fixtures/tls/`. Never trust it.

One image (`Dockerfile`) with vsftpd, proftpd (+ mod_tls) and pure-ftpd. The entrypoint
picks the server from `FTPD_PROFILE` (`profiles/<name>.conf`, see
`courier_ftp_e2e::FtpdProfile`), generates the certificate of `FTPD_CERT`
(`bin/courier-set-cert`: `ca-signed`, `self-signed`, `expired`, `wrong-host`) and runs
the daemon under a supervisor loop, so `courier-set-cert <variant>` can restart it in
place. `--list` prints the profiles, `--check` starts the daemon once and checks its
control port.

- vsftpd profiles: `base/vsftpd.conf` with the profile's keys taking precedence.
- proftpd profiles: `base/proftpd.conf` followed by the profile.
- pure-ftpd profiles: command-line flags, one per line.

Control port 21 (implicit TLS 990), passive ports 30000–30019, PASV address
`FTPD_PASV_ADDRESS` (default: container IP). Users `test`/`test` and
`canary`/`CANARY-PW-e2e-7f3a` are chrooted to their (root-owned) homes with a writable
`upload/` and the read-only `fixtures/` tree (`bin/make-fixture-tree`). Anonymous root:
`/srv/anon` with `readme.txt`. vsftpd has no MLSD: MLSD scenarios use proftpd/pure-ftpd.
