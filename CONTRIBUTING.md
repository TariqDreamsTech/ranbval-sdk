# Contributing to Ranbval SDK

Thank you for your interest in contributing. This document covers how to set up your environment, run tests, and submit changes.

---

## Development Setup

**Requirements:** Python 3.10+, [Poetry](https://python-poetry.org/)

```bash
git clone https://github.com/TariqDreamsTech/ranbval-sdk.git
cd ranbval-sdk
poetry install

# Required — install BOTH hook stages. `pre-commit install` alone installs only
# the commit stage, so the push-time gates (tests, mypy, build) would never run.
pre-commit install --hook-type pre-commit --hook-type pre-push
```

> **`.git/hooks` is not committed.** Every clone starts with no hooks at all, so the line above is
> not optional — a fresh checkout has nothing installed until you run it. CI runs the same hooks
> (see below), so a missed install shows up as a red build rather than a bad merge.

Create a `.ranbval.local` file in the project root with your test credentials:

```bash
RANBVAL_PROJECT_SECRET=your_project_secret
chmod 600 .ranbval.local     # the loader warns otherwise: it is the key to every token
```

---

## The gates

Hooks are split by cost. A commit hook that takes ten seconds gets bypassed with `--no-verify`,
which is exactly the failure this project studies — so the slow checks run at push instead.

| stage | checks |
|---|---|
| **pre-commit** | ruff (lint + format), gitleaks, bandit, `ranbval check`, whitespace/EOL, YAML/TOML/JSON, merge- and case-conflict, large files, `detect-private-key` |
| **pre-push** | mypy, the full test suite, the CHANGELOG-entry gate, and a real `build` + `twine check` |

Run them by hand without committing:

```bash
pre-commit run --all-files                        # commit-stage hooks
pre-commit run --all-files --hook-stage pre-push  # push-stage hooks
```

Or the individual tools:

```bash
poetry run pytest                 # full suite
poetry run pytest tests/test_security_features.py -v
poetry run ruff check .           # lint
poetry run ruff format --check .  # formatting (ruff-format; black is no longer used)
poetry run mypy                   # types
```

**CI runs every hook again**, at both stages, on every push and pull request. That copy is the one
that cannot be skipped: local hooks can be uninstalled, never installed, or bypassed with
`--no-verify`. The local ones exist to give you the same answer in seconds rather than after a
push and a CI queue.

Repo-allowlist enforcement and usage telemetry are server-controlled — there is no client flag to
disable them.

---

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Use type annotations for all public function signatures
- Keep functions focused — one responsibility per function
- Do not import from `src/ranbval_sdk` internals in tests; use the public API from `__init__.py`
- New cryptographic logic must go through the existing `crypto/` package — do not introduce a second encryption path
- Keep each module within its concern subpackage (`config/`, `crypto/`, `policy/`, `serializers/`, `telemetry/`, `integrations/`); only `__init__.py`, `exceptions.py`, and `py.typed` live at the package root
- Respect the **gather → shape → send** split: request bodies are shaped by pure functions in `serializers/` (no I/O), runtime values are gathered elsewhere (e.g. `telemetry/context.py`), and only the client modules do I/O

Formatting is enforced with `ruff` and `black` — run both before opening a PR.

---

## Project Structure

```
ranbval-sdk/
├── src/ranbval_sdk/
│   ├── __init__.py        ← public API surface (all exports live here)
│   ├── exceptions.py      ← RanbvalError hierarchy
│   ├── py.typed           ← PEP 561 type marker
│   ├── config/            ← loader.py + access.py (Vault/inject/secrets) + declarative.py (Secret/SecretConfig)
│   ├── crypto/            ← cipher.py, secret_string.py, audit.py (cryptography only)
│   ├── policy/            ← repo.py (git-remote allowlist enforcement)
│   ├── serializers/       ← telemetry.py, proxy.py, token.py, audit.py (pure wire shaping)
│   ├── telemetry/         ← client.py (emit/aemit), context.py (gather), sampling.py, decorators.py
│   ├── integrations/      ← factory.py, universal.py, proxy.py
│   └── _internal/         ← defaults.py (constants), logging.py, transport.py

├── tests/                 ← pytest suite (+ conftest.py)
├── scripts/               ← manual integration scripts
├── pyproject.toml
└── build.py
```

---

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b fix/describe-your-change
   ```
2. Make your changes. Add or update tests as appropriate.
3. Run the full test suite and confirm it passes.
4. Open a pull request against `main` with a clear title and a short description of what changed and why.

**What we review:**
- Does the change break any existing public API?
- Are new public symbols exported from `__init__.py` intentionally?
- Does it introduce new dependencies? (We keep deps minimal by design.)
- Is the cryptographic behaviour preserved exactly?

---

## Reporting Issues

Open an issue on GitHub with:
- Python version and OS
- Minimal reproduction script
- Full traceback

Do not include real project secrets or vault tokens in issues.
