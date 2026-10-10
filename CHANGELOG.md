# Changelog

All notable changes to courier-ftp are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org). `cd.yml` takes the release notes from
the section matching the tag.

## [Unreleased]

### Added
- CI/CD with the same job set as sverb (T00): fmt, clippy (with and without the
  `sync` feature), docs, tests (Linux, Windows, macOS), cargo-deny, MSRV, crate
  layering, `unsafe` confinement, canary scan, reproducible packaging; nightly
  fuzz and benchmark workflows; a reproducible, multi-platform release pipeline.
- Workspace layout for the protocol, crypto, store, sync and server crates (T01).
- `courier-ftp generate man|completions <shell>`.
- `COURIER_FTP_HOME` redirects the config and data directories.
- Core domain model (T02): `RemotePath`, `LocalPath`, entries, permissions,
  timestamps with precision, protocols, server URLs, credentials, charsets and
  the crate-wide `Error`.
- Typed settings with FileZilla's defaults (T05), loaded leniently and saved as
  a minimal diff; the defaults are listed in `config/default.json`.
- Event and log bus (T04): log levels, command masking, coalesced transfer
  progress, prompts.
- Filename filter engine with FileZilla's built-in filters (T47).
- `Backend` trait, `SessionHandle` with keep-alive and reconnect-once, and an
  in-memory mock backend for tests (T03).
- Local filesystem backend with Windows drive/UNC path mapping, a file name
  sanitizer and a backend conformance suite (T06).
