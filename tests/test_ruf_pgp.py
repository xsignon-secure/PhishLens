"""PGP-encrypted failure reports."""
import shutil
import subprocess
import tempfile

import pytest

from app import models, pgp
from tests.test_fill_gaps import _ARF, _auth, _tenant, client, db  # noqa: F401  (fixtures)


# ------------------------------------------------------------------ PGP for RUF
@pytest.fixture()
def keypair():
    if not pgp.available():
        pytest.skip("gpg not installed")
    home = tempfile.mkdtemp()
    run = lambda *a, **k: subprocess.run(["gpg", "--homedir", home, "--batch", "--yes", *a],
                                         capture_output=True, check=True, **k)
    run("--passphrase", "", "--quick-gen-key", "Security <sec@x.com>", "default", "default", "never")
    pub = run("--armor", "--export", "sec@x.com").stdout.decode()
    yield pub, lambda blob: run("--decrypt", input=blob.encode()).stdout
    shutil.rmtree(home, ignore_errors=True)


def test_pgp_key_validation(keypair):
    pub, _ = keypair
    info = pgp.inspect("Here's our key:\n" + pub)
    assert len(info["fingerprint"]) == 40 and "Security <sec@x.com>" in info["uids"]
    with pytest.raises(pgp.PgpError):
        pgp.inspect("not a key")
    with pytest.raises(pgp.PgpError):
        pgp.inspect(pub.replace("A", "B", 40))


def test_failure_reports_encrypted_to_team_key(client, db, keypair):
    import json
    pub, decrypt = keypair
    h = _auth(client, "o@x.com")
    assert client.put("/api/team/ruf-pgp", json={"key": "nope"}, headers=h).status_code == 400
    r = client.put("/api/team/ruf-pgp", json={"key": pub}, headers=h)
    assert r.status_code == 200 and r.json()["fingerprint"]
    assert client.post("/api/dmarc/forensic", content=_ARF, headers=h).status_code == 201
    row = client.get("/api/dmarc/forensic", headers=h).json()[0]
    assert row["encrypted"] is True and row["subject"] is None and row["header_from"] is None
    assert row["source_ip"] == "198.51.100.7"  # statistics stay readable
    stored = db.query(models.ForensicReport).one()
    assert "Urgent" not in (stored.subject or "") and "ceo@x.com" not in str(stored.auth_results)
    asc = client.get(f"/api/dmarc/forensic/{row['id']}.asc", headers=h)
    assert asc.status_code == 200 and asc.text.startswith("-----BEGIN PGP MESSAGE-----")
    clear = json.loads(decrypt(asc.text))
    assert clear["subject"] == "Urgent wire transfer" and clear["header_from"] == "ceo@x.com"
    assert client.get(f"/api/dmarc/forensic/{row['id']}.asc").status_code == 401


def test_encryption_failure_never_stores_plaintext(client, db, monkeypatch):
    h = _auth(client, "o@x.com")
    t = _tenant(db, "o@x.com")
    t.ruf_pgp_key, t.ruf_pgp_fingerprint = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----", "F" * 40
    db.commit()
    client.post("/api/dmarc/forensic", content=_ARF, headers=h)
    stored = db.query(models.ForensicReport).one()
    assert stored.subject is None and stored.header_from is None and stored.encrypted is None
