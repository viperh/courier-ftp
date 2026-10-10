# Security: what the sync server can see

courier-ftp's optional sync server (`courier-ftp-server`, D12) stores only
end-to-end encrypted data. Sites, passwords, bookmarks, host keys and every
other vault item are sealed on the device with the vault key before upload;
the server never holds a vault key, the master password or the account
private keys. See [threat-model.md](threat-model.md) for the full model.

## What the server stores and sees

| Data | Visible to the server operator |
|---|---|
| Account email | yes (login identifier; CITEXT, unique) |
| OPAQUE registration record | yes, but it reveals nothing about the password without an offline attack per guess (OPAQUE, Argon2id KSF) |
| Account public keys (X25519, Ed25519) | yes |
| Private key bundle, recovery bundle | only as ciphertext (sealed under keys derived from the password / the 24-word recovery key) |
| Vault ids, kinds (personal/team), org, memberships and permissions | yes |
| Wrapped vault keys (grants) and their signatures | only as ciphertext (HPKE to the member's key) |
| Vault names | only as ciphertext |
| Number of items per vault, item ids | yes |
| Item sizes | yes, rounded up to 256 bytes (client-side padding before encryption) |
| Revisions, tombstone flags, timestamps of writes | yes |
| Which device wrote an item, device names and platforms, last-seen times | yes |
| Request timing and client IP addresses (in logs, rate limiting) | yes |
| TOTP secrets | sealed with `COURIER_SERVER_SECRET` (the server can use them, a database dump alone can't) |
| Tokens (access, refresh, reauth), setup and invite tokens, recovery codes | SHA-256 hashes only |

## What the server never sees

- item kinds (site, bookmark, SSH key, ...), names, host names, ports, user
  names, paths, passwords, keys or notes;
- the master password or anything derived from it that would open a bundle;
- vault keys or account private keys.

Each envelope is bound by AEAD associated data to its vault id, item id and
key version, so the server can't move, swap or replay items between vaults
undetected. The server can withhold or roll back data (denial of service);
clients detect stale data through revisions but can't force delivery.

## Operator secrets

`COURIER_SERVER_SECRET` encrypts the OPAQUE server setup and TOTP secrets
in the database. Back up the database **and** the secret together: without
the secret no one can log in, and the server refuses to start with a
different one. The setup token is logged once at `warn` while no account
exists; other tokens are never logged.
