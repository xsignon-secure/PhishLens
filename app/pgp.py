"""OpenPGP encryption of failure (RUF) report details to a team's public key,
using the gpg binary (GnuPG 2.2+). Each call imports the key into a throwaway
keyring, so nothing persists between teams or calls.

Only the team holding the private key can read the encrypted details;
PhishLens never sees it."""
import json
import os
import re
import shutil
import subprocess
import tempfile

MAX_KEY_BYTES = 64 * 1024
TIMEOUT = 20
_ARMOR_RE = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----.+?-----END PGP PUBLIC KEY BLOCK-----", re.DOTALL)


class PgpError(ValueError):
    pass


def available() -> bool:
    return shutil.which("gpg") is not None


def _gpg(home: str, *args: str, data: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["gpg", "--homedir", home, "--batch", "--no-tty", "--quiet", "--no-auto-key-locate",
                           "--no-auto-key-retrieve", *args],
                          input=data, capture_output=True, timeout=TIMEOUT, check=False)


def _with_key(armored: str):
    if not available():
        raise PgpError("GnuPG (gpg) isn't installed on this server")
    m = _ARMOR_RE.search(armored or "")
    if not m or len(m.group(0)) > MAX_KEY_BYTES:
        raise PgpError("Paste an ASCII-armored PGP public key (-----BEGIN PGP PUBLIC KEY BLOCK-----)")
    home = tempfile.mkdtemp(prefix="phishlens-gpg-")
    os.chmod(home, 0o700)
    r = _gpg(home, "--import", data=m.group(0).encode())
    if r.returncode != 0:
        shutil.rmtree(home, ignore_errors=True)
        raise PgpError("That PGP key could not be read")
    return home, m.group(0)


def inspect(armored: str) -> dict:
    """{key, fingerprint, uids} for one public key that can encrypt."""
    home, key = _with_key(armored)
    try:
        out = _gpg(home, "--with-colons", "--fixed-list-mode", "--list-keys").stdout.decode("utf-8", "replace")
    finally:
        shutil.rmtree(home, ignore_errors=True)
    keys, fpr, uids, can_encrypt, current = [], None, [], False, None
    for line in out.splitlines():
        f = line.split(":")
        if f[0] == "pub":
            keys.append(f)
            current = "pub"
            can_encrypt = can_encrypt or ("E" in f[11] and f[1] not in ("r", "e", "i", "d"))
        elif f[0] == "sub":
            current = "sub"
        elif f[0] == "fpr" and current == "pub" and not fpr:
            fpr = f[9]
        elif f[0] == "uid":
            uids.append(f[9])
    if len(keys) != 1:
        raise PgpError("Paste exactly one public key")
    if keys[0][1] in ("r", "e", "i", "d"):
        raise PgpError("That key is revoked, expired or invalid")
    if not can_encrypt:
        raise PgpError("That key has no usable encryption subkey")
    return {"key": key, "fingerprint": fpr, "uids": uids[:5]}


def encrypt(armored: str, fingerprint: str, payload: dict) -> str:
    home, _ = _with_key(armored)
    try:
        r = _gpg(home, "--trust-model", "always", "--armor", "--encrypt", "--recipient", fingerprint,
                 data=json.dumps(payload, indent=1).encode())
    finally:
        shutil.rmtree(home, ignore_errors=True)
    if r.returncode != 0 or not r.stdout:
        raise PgpError("Encryption failed: " + r.stderr.decode("utf-8", "replace")[:200])
    return r.stdout.decode()
