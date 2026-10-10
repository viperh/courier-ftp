#!/usr/bin/env python3
"""Writes the key-format fixtures of this directory (T20) from the T76 sshd fixture keys.

TEST-ONLY key material. The keys are the ones in `tests/fixtures/sshd/keys/` (so the
public keys are in that image's `authorized_keys`); this script only re-encodes them:

- copies: id_ed25519, id_ed25519_enc (= id_ed25519_encrypted, passphrase `fixture`),
  id_ecdsa_p256 (= id_ecdsa), id_rsa4096 (= id_rsa), id_ed25519.ppk (PuTTY v2) and
  id_ed25519_v3.ppk (PuTTY v3);
- PEM: id_rsa_pkcs1.pem (PKCS#1), id_rsa_pkcs1_enc.pem (legacy `Proc-Type: 4,ENCRYPTED`,
  AES-256-CBC), id_ec_sec1.pem (SEC1), id_ed25519_pkcs8.pem (PKCS#8),
  id_rsa_pkcs8_enc.pem (PKCS#8 PBES2);
- PuTTY: id_rsa_v2_enc.ppk (v2, AES-256-CBC) and id_ecdsa_v3_enc.ppk (v3, Argon2id);
- fingerprints.txt: `<file> SHA256:<fingerprint>` for every fixture;
- canary_ed25519_pkcs8_enc.pem: the id_ed25519 key as encrypted PKCS#8 with the
  passphrase `CANARY-PP-t20-5d1c` (the loopback canary test, AC16);
- unsupported keys (generated, not authorized anywhere): unsupported_dsa.pem,
  unsupported_dsa_openssh, unsupported_rsa1024.pem.

Encrypted fixtures use the passphrase `fixture`. Needs the Python `cryptography`
package (no bcrypt: only unencrypted OpenSSH keys are read).

Usage (from the repository root): python3 -I crates/courier-ftp-proto-sftp/tests/keys/derive.py
"""

import base64
import hashlib
import hmac
import os
import shutil
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "..", "..", "..", "tests", "fixtures", "sshd", "keys")
PASS = b"fixture"
COMMENT = "courier-ftp-e2e-fixture-TEST-ONLY"


def write(name, data):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(data)


def load(name):
    with open(os.path.join(SRC, name), "rb") as f:
        return serialization.load_ssh_private_key(f.read(), password=None)


def u32(n):
    return struct.pack(">I", n)


def sshstr(b):
    return u32(len(b)) + b


def mpint(n):
    if n == 0:
        return sshstr(b"")
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return sshstr(b)


def lines64(blob):
    text = base64.b64encode(blob).decode()
    return [text[i : i + 64] for i in range(0, len(text), 64)]


def ppk(algo, public, private, version, comment, password):
    """A PuTTY key file (PuTTY's ppk_save_sb)."""
    header = []
    if password:
        encryption = "aes256-cbc"
        private += hashlib.sha1(private).digest()[: (-len(private)) % 16]
        if version == 2:
            h0 = hashlib.sha1(u32(0) + password).digest()
            h1 = hashlib.sha1(u32(1) + password).digest()
            key, iv = (h0 + h1)[:32], b"\x00" * 16
            mac_key = hashlib.sha1(b"putty-private-key-file-mac-key" + password).digest()
        else:
            # A fixed salt keeps reruns stable.
            salt = bytes(range(16))
            mem, passes, par = 8192, 2, 1
            okm = Argon2id(
                salt=salt, length=80, iterations=passes, lanes=par, memory_cost=mem
            ).derive(password)
            key, iv, mac_key = okm[:32], okm[32:48], okm[48:80]
            header = [
                "Key-Derivation: Argon2id",
                f"Argon2-Memory: {mem}",
                f"Argon2-Passes: {passes}",
                f"Argon2-Parallelism: {par}",
                f"Argon2-Salt: {salt.hex()}",
            ]
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        blob = enc.update(private) + enc.finalize()
    else:
        encryption = "none"
        blob = private
        mac_key = (
            hashlib.sha1(b"putty-private-key-file-mac-key").digest() if version == 2 else b""
        )
    mac_data = (
        sshstr(algo.encode())
        + sshstr(encryption.encode())
        + sshstr(comment.encode())
        + sshstr(public)
        + sshstr(private)
    )
    digest = hashlib.sha1 if version == 2 else hashlib.sha256
    mac = hmac.new(mac_key, mac_data, digest).hexdigest()
    pub_lines = lines64(public)
    priv_lines = lines64(blob)
    out = [
        f"PuTTY-User-Key-File-{version}: {algo}",
        f"Encryption: {encryption}",
        f"Comment: {comment}",
        f"Public-Lines: {len(pub_lines)}",
        *pub_lines,
        *header,
        f"Private-Lines: {len(priv_lines)}",
        *priv_lines,
        f"Private-MAC: {mac}",
    ]
    return ("\n".join(out) + "\n").encode()


def rsa_ppk(key, version, comment, password):
    pn = key.private_numbers()
    public = sshstr(b"ssh-rsa") + mpint(pn.public_numbers.e) + mpint(pn.public_numbers.n)
    private = mpint(pn.d) + mpint(pn.p) + mpint(pn.q) + mpint(pn.iqmp)
    return ppk("ssh-rsa", public, private, version, comment, password)


def ecdsa_ppk(key, version, comment, password):
    point = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    algo = "ecdsa-sha2-nistp256"
    public = sshstr(algo.encode()) + sshstr(b"nistp256") + sshstr(point)
    private = mpint(key.private_numbers().private_value)
    return ppk(algo, public, private, version, comment, password)


def pem(key, fmt, password=None):
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(serialization.Encoding.PEM, fmt, enc)


def fingerprint(key):
    blob = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).split()[1]
    digest = hashlib.sha256(base64.b64decode(blob)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def main():
    ed = load("id_ed25519")
    ecdsa = load("id_ecdsa")
    rsa_key = load("id_rsa")
    assert isinstance(ecdsa, ec.EllipticCurvePrivateKey)
    assert isinstance(rsa_key, rsa.RSAPrivateKey)
    for src, dst in [
        ("id_ed25519", "id_ed25519"),
        ("id_ed25519_encrypted", "id_ed25519_enc"),
        ("id_ecdsa", "id_ecdsa_p256"),
        ("id_rsa", "id_rsa4096"),
        ("id_ed25519.ppk", "id_ed25519.ppk"),
        ("id_ed25519_v3.ppk", "id_ed25519_v3.ppk"),
    ]:
        shutil.copyfile(os.path.join(SRC, src), os.path.join(HERE, dst))
    trad = serialization.PrivateFormat.TraditionalOpenSSL
    pkcs8 = serialization.PrivateFormat.PKCS8
    write("id_rsa_pkcs1.pem", pem(rsa_key, trad))
    write("id_rsa_pkcs1_enc.pem", pem(rsa_key, trad, PASS))
    write("id_ec_sec1.pem", pem(ecdsa, trad))
    write("id_ed25519_pkcs8.pem", pem(ed, pkcs8))
    write("id_rsa_pkcs8_enc.pem", pem(rsa_key, pkcs8, PASS))
    write("id_rsa_v2_enc.ppk", rsa_ppk(rsa_key, 2, COMMENT, PASS))
    write("id_ecdsa_v3_enc.ppk", ecdsa_ppk(ecdsa, 3, COMMENT, PASS))

    write("canary_ed25519_pkcs8_enc.pem", pem(ed, pkcs8, b"CANARY-PP-t20-5d1c"))

    # Negative fixtures. They change on every run (fresh keys); nothing trusts them.
    dsa_key = dsa.generate_private_key(key_size=1024)
    write("unsupported_dsa.pem", pem(dsa_key, trad))
    write("unsupported_dsa_openssh", pem(dsa_key, serialization.PrivateFormat.OpenSSH))
    write("unsupported_rsa1024.pem", pem(rsa.generate_private_key(65537, 1024), trad))

    # The encrypted OpenSSH key's fingerprint comes from its .pub (no bcrypt here).
    with open(os.path.join(SRC, "id_ed25519_encrypted.pub"), "rb") as f:
        enc_pub = base64.b64decode(f.read().split()[1])
    enc_fp = "SHA256:" + base64.b64encode(hashlib.sha256(enc_pub).digest()).decode().rstrip("=")
    rows = [
        ("id_ed25519", fingerprint(ed)),
        ("id_ed25519_enc", enc_fp),
        ("id_ecdsa_p256", fingerprint(ecdsa)),
        ("id_rsa4096", fingerprint(rsa_key)),
        ("id_rsa_pkcs1.pem", fingerprint(rsa_key)),
        ("id_rsa_pkcs1_enc.pem", fingerprint(rsa_key)),
        ("id_ec_sec1.pem", fingerprint(ecdsa)),
        ("id_ed25519_pkcs8.pem", fingerprint(ed)),
        ("id_rsa_pkcs8_enc.pem", fingerprint(rsa_key)),
        ("id_ed25519.ppk", fingerprint(ed)),
        ("id_ed25519_v3.ppk", fingerprint(ed)),
        ("id_rsa_v2_enc.ppk", fingerprint(rsa_key)),
        ("id_ecdsa_v3_enc.ppk", fingerprint(ecdsa)),
    ]
    write("fingerprints.txt", "".join(f"{n} {fp}\n" for n, fp in rows).encode())


if __name__ == "__main__":
    main()
