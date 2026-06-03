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
RANBVAL_SKIP_REPO_CHECK=1
```

---

## Running Tests

```bash
# Run all tests
poetry run python -m pytest

# Run a specific test file
poetry run python -m pytest test_security_features.py -v

# Run with output (useful when debugging SecretString behaviour)
poetry run python test_secret_string.py
```

All tests must pass before submitting a pull request. Do not disable the repo check or telemetry in production code paths.

---

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Use type annotations for all public function signatures
- Keep functions focused — one responsibility per function
- Do not import from `src/ranbval_sdk` internals in tests; use the public API from `__init__.py`
- New cryptographic logic must go through the existing `crypto.py` module — do not introduce a second encryption path

Formatting is not currently enforced by a linter, but please keep diffs clean and consistent with the surrounding code.

---

## Project Structure

```
ranbval-sdk/
├── src/ranbval_sdk/
│   ├── __init__.py        ← public API surface (all exports live here)
│   ├── crypto.py          ← AES-256-GCM + PBKDF2 decrypt logic
│   ├── secret_string.py   ← SecretString wrapper
│   ├── dot_ranbval.py     ← .ranbval file loader and layer merge
│   ├── telemetry.py       ← emit_telemetry() implementation
│   ├── audit.py           ← in-process audit log
│   ├── proxy.py           ← proxy_request() and ProxyError
│   ├── repo_policy.py     ← git remote allowlist check
│   ├── http_tls.py        ← TLS-verified HTTP helpers
│   ├── defaults.py        ← env var defaults and constants
│   └── integrations/      ← secure_client / build_secure_client
├── test_*.py              ← test files (pytest)
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
- Minimal reproduction script (use `RANBVAL_SKIP_REPO_CHECK=1` and a dummy token if needed)
- Full traceback

Do not include real project secrets or vault tokens in issues.
