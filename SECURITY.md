# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

- preferred: GitHub's private vulnerability reporting
  ("Security" tab → "Report a vulnerability") on
  <https://github.com/viperh/courier-ftp>;
- or email the maintainer at olteanromeodavid34@gmail.com (the address in `Cargo.toml`).

Include the courier-ftp version (`courier-ftp --version`), your OS, and steps or a file
that reproduces the problem. Please don't include real passwords, keys or vault files.

You will get an answer within 7 days. Fixes are released as soon as they are ready, and
the advisory credits the reporter unless they ask otherwise.

## Supported versions

Only the latest release gets security fixes.

## Scope

In scope: the `courier-ftp` client (vault, crypto, SSH/SFTP, FTP/FTPS, proxies, the TUI)
and, once released, the sync server. How courier-ftp protects secrets, what it assumes and
which risks it accepts is described in [`docs/threat-model.md`](docs/threat-model.md).

Known, accepted limitations (see the threat model's "Residual risks") are not
vulnerabilities by themselves, for example: plain FTP sends credentials in clear text;
debug logs contain hostnames; `mlock` is best effort.
