#!/usr/bin/env python3
"""Independent re-derivation of courier-ftp-crypto's known-answer vectors (T80).

A second implementation of every format in `crates/courier-ftp-crypto/tests/kat/*.json`
that does not involve zstd: canonical encodings, HKDF (RFC 5869 and item keys), key
wraps, device blobs (the AEAD layer over the recorded zstd payload), pad256, the
account KEK, private and recovery bundles, fingerprints and safety numbers, and the
grant signature message. It uses only the standard library (`hashlib`, `hmac`) plus
`cryptography`'s ChaCha20-Poly1305; HChaCha20 (and so XChaCha20-Poly1305) is written
by hand from draft-irtf-cfrg-xchacha-03.

The Rust generators (`cargo test -p courier-ftp-crypto --test kat -- --ignored`) write
the vectors; this script only checks them, so a bug shared by the Rust code and its own
generator still shows up here.

Usage: python3 scripts/kat/gen_crypto.py --check [--kat-dir DIR]
Exit code 0 = every vector matches, 1 = mismatch, 2 = usage error,
3 = the `cryptography` package is missing.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import pathlib
import struct
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:  # pragma: no cover - environment dependent
    print("gen_crypto.py: the `cryptography` package is not installed", file=sys.stderr)
    sys.exit(3)

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_KAT_DIR = ROOT / "crates" / "courier-ftp-crypto" / "tests" / "kat"

# Labels (crates/courier-ftp-crypto/src/canon.rs). Written without a length prefix.
ITEM_V1 = b"courier-ftp-item-v1"
ITEM_KEY_V1 = b"courier-ftp/item/v1"
LMK_WRAP_V1 = b"courier-ftp-lmk-wrap-v1"
DEVICE_BLOB_V1 = b"courier-ftp-device-blob-v1"
VK_V1 = b"courier-ftp/vk/v1"
GRANT_V1 = b"courier-ftp/grant/v1"
AKEK_V1 = b"courier-ftp/akek/v1"
BUNDLE_V1 = b"courier-ftp/bundle/v1"
RECOVERY_V1 = b"courier-ftp/recovery/v1"
RECOVERY_BUNDLE_V1 = b"courier-ftp/recovery-bundle/v1"
FPR_V1 = b"courier-ftp/fpr/v1"


# --------------------------------------------------------------- primitives --


def u32(v: int) -> bytes:
    return struct.pack(">I", v)


def lp(b: bytes) -> bytes:
    return u32(len(b)) + b


def hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _rotl(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _qr(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20 (draft-irtf-cfrg-xchacha-03 §2.2)."""
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(s, 0, 4, 8, 12)
        _qr(s, 1, 5, 9, 13)
        _qr(s, 2, 6, 10, 14)
        _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15)
        _qr(s, 1, 6, 11, 12)
        _qr(s, 2, 7, 8, 13)
        _qr(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def xchacha_seal(key: bytes, nonce24: bytes, aad: bytes, pt: bytes) -> bytes:
    sub = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(sub).encrypt(b"\x00" * 4 + nonce24[16:], pt, aad)


def self_test() -> list[str]:
    """The draft's own vectors, so a broken HChaCha20 fails loudly."""
    errors = []
    k = bytes(range(32))
    got = hchacha20(k, bytes.fromhex("000000090000004a0000000031415927"))
    if got.hex() != "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc":
        errors.append("HChaCha20 draft §2.2.1")
    pt = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip"
        b" for the future, sunscreen would be it."
    )
    ct = xchacha_seal(
        bytes(range(0x80, 0xA0)),
        bytes(range(0x40, 0x58)),
        bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
        pt,
    )
    if not ct.hex().endswith("c0875924c1c7987947deafd8780acf49") or not ct.hex().startswith(
        "bd6d179d3e83d43b9576579493c0e939"
    ):
        errors.append("XChaCha20-Poly1305 draft A.3.1")
    return errors


# ------------------------------------------------------------ constructions --


def aad_wrap(name: str, vault_id: bytes | None) -> bytes:
    return LMK_WRAP_V1 + lp(name.encode()) + (vault_id or b"")


def wrap_aad_for(v: dict) -> bytes:
    p = v["purpose"]
    vid = bytes.fromhex(v["purpose_vault_id"]) if p == "vault-key" else None
    return aad_wrap(p, vid)


def item_key(vk: bytes, item_id: bytes) -> bytes:
    return hkdf(vk, item_id, ITEM_KEY_V1, 32)


def aad_device_blob(name: str) -> bytes:
    return DEVICE_BLOB_V1 + lp(name.encode())


def pad256(b: bytes) -> bytes:
    n = (len(b) // 256 + 1) * 256
    return (b + b"\x80").ljust(n, b"\x00")


def bundle_cbor(x_sk: bytes, e_sk: bytes) -> bytes:
    return (
        b"\xa2\x69x25519_sk\x58\x20" + x_sk + b"\x6aed25519_sk\x58\x20" + e_sk
    )


def fingerprint(x_pub: bytes, e_pub: bytes) -> bytes:
    return hashlib.sha256(FPR_V1 + x_pub + e_pub).digest()


def safety_number(a: bytes, b: bytes) -> str:
    lo, hi = sorted([a, b])
    groups = []
    for f in (lo, hi):
        for i in range(6):
            n = int.from_bytes(f[5 * i : 5 * i + 5], "big") % 100_000
            groups.append(f"{n:05d}")
    return " ".join(groups)


# ------------------------------------------------------------------- checks --


def load(kat_dir: pathlib.Path, name: str) -> list[dict]:
    return json.loads((kat_dir / name).read_text())["vectors"]


def h(v: dict, k: str) -> bytes:
    return bytes.fromhex(v[k])


def check_hkdf(kat: pathlib.Path) -> list[str]:
    errs = []
    for i, v in enumerate(load(kat, "hkdf.json")):
        if v["kind"] == "raw":
            salt = bytes.fromhex(v["salt"]) if v["salt"] is not None else None
            got = hkdf(h(v, "ikm"), salt, h(v, "info"), v["len"])
        elif v["kind"] == "item_key":
            got = item_key(h(v, "vk"), h(v, "item_id"))
        else:
            errs.append(f"hkdf[{i}]: unknown kind {v['kind']}")
            continue
        if got.hex() != v["okm"]:
            errs.append(f"hkdf[{i}] ({v['kind']})")
    return errs


def check_canon(kat: pathlib.Path) -> list[str]:
    errs = []
    for i, v in enumerate(load(kat, "canon.json")):
        k = v["kind"]
        if k == "aad_item":
            got = ITEM_V1 + h(v, "vault_id") + h(v, "item_id") + u32(v["key_version"])
        elif k == "info_item_key":
            got = ITEM_KEY_V1
        elif k == "info_akek":
            got = AKEK_V1
        elif k == "info_recovery_key":
            got = RECOVERY_V1
        elif k == "info_vk":
            got = VK_V1 + h(v, "vault_id") + u32(v["key_version"])
        elif k == "aad_wrap":
            got = wrap_aad_for(v)
        elif k == "aad_private_bundle":
            got = BUNDLE_V1 + h(v, "user_id") + u32(v["version"])
        elif k == "aad_recovery_bundle":
            got = RECOVERY_BUNDLE_V1 + h(v, "user_id")
        elif k == "sig_grant":
            got = (
                GRANT_V1
                + h(v, "vault_id")
                + h(v, "member_id")
                + u32(v["key_version"])
                + lp(h(v, "wrapped"))
            )
        elif k == "fpr_input":
            got = FPR_V1 + h(v, "x25519_pub") + h(v, "ed25519_pub")
        elif k == "aad_device_blob":
            got = aad_device_blob(v["name"])
        elif k == "len_prefixed":
            got = lp(h(v, "input"))
        else:
            errs.append(f"canon[{i}]: unknown kind {k}")
            continue
        if got.hex() != v["output"]:
            errs.append(f"canon[{i}] ({k})")
    return errs


def check_wrap(kat: pathlib.Path) -> list[str]:
    errs = []
    for i, v in enumerate(load(kat, "wrap.json")):
        n = h(v, "nonce")
        got = n + xchacha_seal(h(v, "kek"), n, wrap_aad_for(v), h(v, "secret"))
        if got.hex() != v["wrapped"]:
            errs.append(f"wrap[{i}] ({v['purpose']})")
    return errs


def check_device_blob(kat: pathlib.Path) -> list[str]:
    errs = []
    for i, v in enumerate(load(kat, "device_blob.json")):
        n = h(v, "nonce")
        ct = xchacha_seal(h(v, "device_key"), n, aad_device_blob(v["name"]), h(v, "compressed"))
        if (b"\x01" + n + ct).hex() != v["blob"]:
            errs.append(f"device_blob[{i}] ({v['name']})")
    return errs


def check_pad(kat: pathlib.Path) -> list[str]:
    return [
        f"pad[{i}]"
        for i, v in enumerate(load(kat, "pad.json"))
        if pad256(h(v, "input")).hex() != v["output"]
    ]


def check_account(kat: pathlib.Path) -> list[str]:
    errs = []
    for i, v in enumerate(load(kat, "account.json")):
        k = v["kind"]
        if k == "akek":
            if hkdf(h(v, "export_key"), None, AKEK_V1, 32).hex() != v["akek"]:
                errs.append(f"account[{i}] akek")
        elif k == "bundle":
            akek = hkdf(h(v, "export_key"), None, AKEK_V1, 32)
            aad = BUNDLE_V1 + h(v, "user_id") + u32(int(v["version"]))
            b = h(v, "bundle")
            pt = bundle_cbor(h(v, "x25519_sk"), h(v, "ed25519_sk"))
            got = b"\x01" + b[1:25] + xchacha_seal(akek, b[1:25], aad, pt)
            if akek.hex() != v["akek"] or aad.hex() != v["aad"] or got != b or len(b) != 131:
                errs.append(f"account[{i}] bundle")
        elif k == "recovery":
            kek = hkdf(h(v, "recovery_key"), None, RECOVERY_V1, 32)
            aad = RECOVERY_BUNDLE_V1 + h(v, "user_id")
            b = h(v, "bundle")
            pt = bundle_cbor(h(v, "x25519_sk"), h(v, "ed25519_sk"))
            got = b"\x01" + b[1:25] + xchacha_seal(kek, b[1:25], aad, pt)
            if kek.hex() != v["recovery_kek"] or aad.hex() != v["aad"] or got != b:
                errs.append(f"account[{i}] recovery")
        elif k == "grant":
            vault, member = h(v, "vault_id"), h(v, "member_id")
            kv = int(v["key_version"])
            wrapped = h(v, "wrapped")
            info = VK_V1 + vault + u32(kv)
            msg = GRANT_V1 + vault + member + u32(kv) + lp(wrapped)
            ok = info.hex() == v["hpke_info"] and msg.hex() == v["sig_message"]
            ok = ok and h(v, "grant_bytes") == lp(wrapped) + h(v, "signature")
            ok = ok and len(wrapped) == 88 and wrapped[:4] == u32(32)
            try:
                Ed25519PublicKey.from_public_bytes(h(v, "granter_ed25519_pub")).verify(
                    h(v, "signature"), msg
                )
            except Exception:  # noqa: BLE001 - any failure is a mismatch
                ok = False
            if not ok:
                errs.append(f"account[{i}] grant")
        elif k == "fingerprint":
            fa = fingerprint(h(v, "a_x25519_pub"), h(v, "a_ed25519_pub"))
            fb = fingerprint(h(v, "b_x25519_pub"), h(v, "b_ed25519_pub"))
            ok = fa.hex() == v["a_fingerprint"] and fb.hex() == v["b_fingerprint"]
            if not ok or safety_number(fa, fb) != v["safety_number"]:
                errs.append(f"account[{i}] fingerprint")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="verify the KAT files")
    ap.add_argument("--kat-dir", type=pathlib.Path, default=DEFAULT_KAT_DIR)
    args = ap.parse_args()
    if not args.check:
        ap.print_usage(sys.stderr)
        return 2
    errors = self_test()
    for check in (
        check_hkdf,
        check_canon,
        check_wrap,
        check_device_blob,
        check_pad,
        check_account,
    ):
        errors += check(args.kat_dir)
    # The unit-test vectors from the task file.
    if item_key(bytes(range(32)), b"\x11" * 16).hex() != (
        "7b222ec99fd60b6ce6eb3147e24e30f347414ac1ed8187d557eaf1b42221ae43"
    ):
        errors.append("item_key unit vector")
    if hkdf(b"\x42" * 32, None, RECOVERY_V1, 32).hex() != (
        "9864cdbedd5ce9a21e3a2f57cbe3e16295af9651721596775caf8eebdf506292"
    ):
        errors.append("recovery kek unit vector")
    for e in errors:
        print(f"MISMATCH: {e}", file=sys.stderr)
    if errors:
        return 1
    print("courier-ftp-crypto KATs re-derived independently: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
