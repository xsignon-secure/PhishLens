#!/usr/bin/env python3
"""Domain Connect setup helper (see docs/DOMAIN-CONNECT.md).

    python scripts/domain_connect.py keygen
        Prints a new RSA private key (for DOMAIN_CONNECT_PRIVATE_KEY) and the
        TXT records to publish at <DOMAIN_CONNECT_KEY_ID>.<DOMAIN_CONNECT_KEY_DOMAIN>.

    python scripts/domain_connect.py templates OUT_DIR
        Writes one template per record kind, named <providerId>.<serviceId>.json,
        ready for a pull request to github.com/Domain-Connect/Templates.
        Uses DOMAIN_CONNECT_PROVIDER_ID, DOMAIN_CONNECT_KEY_DOMAIN and APP_URL.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import domain_connect  # noqa: E402
from app.config import settings  # noqa: E402


def keygen() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    host = f"{settings.DOMAIN_CONNECT_KEY_ID}.{settings.DOMAIN_CONNECT_KEY_DOMAIN or '<DOMAIN_CONNECT_KEY_DOMAIN>'}"
    print("# DOMAIN_CONNECT_PRIVATE_KEY (keep secret; one line with \\n escapes is fine):")
    print(private.replace("\n", "\\n"))
    print(f"\n# Publish these TXT records at {host}:")
    for value in domain_connect.public_key_records(public):
        print(f'{host}  TXT  "{value}"')


def templates(out_dir: str) -> None:
    if not (settings.DOMAIN_CONNECT_PROVIDER_ID and settings.DOMAIN_CONNECT_KEY_DOMAIN):
        sys.exit("Set DOMAIN_CONNECT_PROVIDER_ID and DOMAIN_CONNECT_KEY_DOMAIN first.")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for service_id in domain_connect.SERVICES:
        path = out / f"{settings.DOMAIN_CONNECT_PROVIDER_ID}.{service_id}.json"
        path.write_text(json.dumps(domain_connect.template(service_id), indent=2) + "\n")
        print(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    t = sub.add_parser("templates")
    t.add_argument("out_dir")
    args = parser.parse_args()
    keygen() if args.cmd == "keygen" else templates(args.out_dir)
