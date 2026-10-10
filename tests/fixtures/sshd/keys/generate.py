#!/usr/bin/env python3
"""Regenerate the TEST-ONLY SSH fixture keys (needs `cryptography`, e.g. 50.0.1).

Usage: python3 generate.py   (run inside tests/fixtures/sshd/keys)

Writes id_ed25519, id_ecdsa (P-256), id_rsa (4096), id_ed25519_encrypted (passphrase
`fixture`), the PuTTY files id_ed25519.ppk (v2), id_ed25519_v3.ppk (v3) and
id_ed25519_v3_encrypted.ppk (v3, Argon2id, passphrase `fixture`) of the id_ed25519 key,
every `.pub`, and authorized_keys. The PPK writer follows PuTTY's format
(https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixC.html); the files are
equivalent to `puttygen id_ed25519 -O private --ppk-param version=2|3`.
"""

import base64
import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

COMMENT = "courier-ftp-e2e-fixture-TEST-ONLY"
PASSPHRASE = b"fixture"


def write(name, data, mode=0o600):
    with open(name, "wb") as f:
        f.write(data)
    os.chmod(name, mode)


def openssh(key, name, comment, password=None):
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    write(
        name,
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, enc
        ),
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    line = pub.decode() + " " + comment + "\n"
    write(name + ".pub", line.encode(), 0o644)
    return line


def sshstr(b):
    return struct.pack(">I", len(b)) + b


def lines64(blob):
    text = base64.b64encode(blob).decode()
    return [text[i : i + 64] for i in range(0, len(text), 64)]


def ppk(key, version, comment, password=None):
    algo = "ssh-ed25519"
    raw_pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    seed = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = sshstr(algo.encode()) + sshstr(raw_pub)
    # PuTTY writes the Ed25519 private key as its 32 raw bytes in an SSH string.
    private = sshstr(seed)
    header = []
    if password:
        encryption = "aes256-cbc"
        private += hashlib.sha1(private).digest()[: (-len(private)) % 16]
        salt = os.urandom(16)
        mem, passes, par = 8192, 8, 1
        okm = Argon2id(
            salt=salt, length=80, iterations=passes, lanes=par, memory_cost=mem
        ).derive(password)
        key_, iv, mac_key = okm[:32], okm[32:48], okm[48:80]
        enc = Cipher(algorithms.AES(key_), modes.CBC(iv)).encryptor()
        cipher_blob = enc.update(private) + enc.finalize()
        header = [
            "Key-Derivation: Argon2id",
            f"Argon2-Memory: {mem}",
            f"Argon2-Passes: {passes}",
            f"Argon2-Parallelism: {par}",
            f"Argon2-Salt: {salt.hex()}",
        ]
    else:
        encryption = "none"
        cipher_blob = private
        mac_key = (
            hashlib.sha1(b"putty-private-key-file-mac-key").digest()
            if version == 2
            else b""
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
    priv_lines = lines64(cipher_blob)
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


def main():
    ed = ed25519.Ed25519PrivateKey.generate()
    keys = [
        openssh(ed, "id_ed25519", COMMENT),
        openssh(ec.generate_private_key(ec.SECP256R1()), "id_ecdsa", COMMENT),
        openssh(
            rsa.generate_private_key(public_exponent=65537, key_size=4096),
            "id_rsa",
            COMMENT,
        ),
        openssh(
            ed25519.Ed25519PrivateKey.generate(),
            "id_ed25519_encrypted",
            COMMENT + "-encrypted",
            PASSPHRASE,
        ),
    ]
    write("authorized_keys", "".join(keys).encode(), 0o644)
    write("id_ed25519.ppk", ppk(ed, 2, COMMENT))
    write("id_ed25519_v3.ppk", ppk(ed, 3, COMMENT))
    write("id_ed25519_v3_encrypted.ppk", ppk(ed, 3, COMMENT, PASSPHRASE))


if __name__ == "__main__":
    main()
