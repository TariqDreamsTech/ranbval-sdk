# Contributing to Ranbval SDK

Thank you for your interest in contributing. This document covers how to set up your environment, run tests, and submit changes.

---

## Development Setup

**Requirements:** Python 3.10+, [Poetry](https://python-poetry.org/)

```bash
git clone https://github.com/TariqDreamsTech/ranbval-sdk.git
cd ranbval-sdk
poetry install
```

Create a `.ranbval.local` file in the project root with your test credentials:

```bash
RANBVAL_PROJECT_SECRET=your_project_secret
```

---

## Running Tests

```bash
# Run all tests (discovered from tests/)
poetry run pytest

# Run a specific test file
poetry run pytest tests/test_security_features.py -v

# Lint and format checks
poetry run ruff check src
poetry run black --check src
```

All tests, `ruff`, and `black` must pass before submitting a pull request. Repo-allowlist
enforcement and usage telemetry are always on and server-controlled — there is no client
flag to disable them.

---

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Use type annotations for all public function signatures
- Keep functions focused — one responsibility per function
- Do not import from `src/ranbval_sdk` internals in tests; use the public API from `__init__.py`
- New cryptographic logic must go through the existing `crypto/` package — do not introduce a second encryption path
- Keep each module within its concern subpackage (`config/`, `crypto/`, `telemetry/`, `integrations/`); only `__init__.py`, `exceptions.py`, and `py.typed` live at the package root

Formatting is enforced with `ruff` and `black` — run both before opening a PR.

---

## Project Structure

```
ranbval-sdk/
├── src/ranbval_sdk/
│   ├── __init__.py        ← public API surface (all exports live here)
│   ├── exceptions.py      ← RanbvalError hierarchy
│   ├── py.typed           ← PEP 561 type marker
│   ├── config/            ← loader.py (.ranbval loading) + access.py (Vault/inject/secrets)
│   ├── crypto/            ← cipher.py, secret_string.py, audit.py, repo_policy.py
│   ├── telemetry/         ← client.py (emit/aemit) + decorators.py (@track/tracked)
│   ├── integrations/      ← factory.py, universal.py, proxy.py
│   └── _internal/         ← defaults.py, transport.py (private cross-cutting utils)
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
