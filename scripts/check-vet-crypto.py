#!/usr/bin/env python3
"""cargo-vet crypto policy (T00; adapted from sverb).

Crypto crates should be vetted `safe-to-deploy` through an imported or our own
audit. Until those audits exist they may be exempted, so this script reports every
exempted crypto crate as a CI warning instead of failing. Set VET_CRYPTO_STRICT=1 to
make it fail once the audits are in. Run it after `cargo vet --locked`.

Usage: python3 scripts/check-vet-crypto.py [supply-chain/config.toml]
Exit code 0 = ok (or warnings), 1 = strict failure / unreadable config, 2 = usage error.
"""

from __future__ import annotations

import os
import sys
import tomllib

# Crypto and TLS/SSH building blocks (D3, D9, D2). Their RustCrypto helpers (digest,
# hmac, aead, ...) may stay exempted for now; the list is reviewed each milestone.
CRYPTO = {
    "chacha20poly1305",
    "argon2",
    "hkdf",
    "sha2",
    "hpke",
    "opaque-ke",
    "x25519-dalek",
    "ed25519-dalek",
    "rand_core",
    "zeroize",
    "secrecy",
    "bip39",
    "zxcvbn",
    "rustls",
    "ring",
    "russh",
}


def usage() -> int:
    print(__doc__, file=sys.stderr)
    return 2


def main(argv: list[str]) -> int:
    if len(argv) > 1 or (argv and argv[0].startswith("-")):
        return usage()
    path = argv[0] if argv else "supply-chain/config.toml"
    try:
        with open(path, "rb") as fh:
            config = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as err:
        print(f"{path}: cannot read cargo-vet config: {err}", file=sys.stderr)
        return 1
    exempted = sorted(set(config.get("exemptions", {})) & CRYPTO)
    if exempted:
        message = (
            "crypto crates are exempted, not audited: "
            f"{', '.join(exempted)}. Import an audit (cargo vet suggest) or certify one "
            "(cargo vet certify)."
        )
        if os.environ.get("VET_CRYPTO_STRICT") == "1":
            print(message, file=sys.stderr)
            return 1
        print(f"::warning::{message}")
        return 0
    print("cargo-vet crypto policy OK: no crypto crate is exempted")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
