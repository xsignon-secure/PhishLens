# Contributing to PhishLens

Thanks for helping. PhishLens is free and open source under the MIT License,
and every feature is available to everyone: please keep it that way (no
paywalls, tracking or vendor pitches in contributions).

## Set up

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env            # set SECRET_KEY
.venv/bin/uvicorn app.main:app --reload --port 8000
.venv/bin/python -m pytest tests/ -q
```

Tests never touch the network or your `phishlens.db`: DNS and HTTP are stubbed.

## Good first contributions

- A new check or a sharper fix suggestion in `app/scanner/`
- More DNS providers for one-click fixes (`app/dns_providers.py`: Route 53,
  DigitalOcean, deSEC...)
- Translations of the UI text in `app/templates/`
- Docs: deploy guides for more free hosts

## Pull requests

- One topic per pull request, with a test for the change.
- Schema changes need an Alembic migration:
  `alembic revision --autogenerate -m "..."`, then check `alembic check` is clean.
- Match the surrounding style: small functions, plain names, vanilla JS (no
  build step), no new external services without an opt-in setting.
- CI runs the test suite, the migrations and a Docker build on every pull request.

## Security issues

Don't open public issues for vulnerabilities: see [SECURITY.md](SECURITY.md).

By contributing you agree that your contribution is licensed under the MIT License.
