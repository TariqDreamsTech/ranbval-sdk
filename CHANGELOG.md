# Changelog

All notable changes to `ranbval-sdk` are documented here.

---

## [2.1.1] - 2026-07-09

### Fixed
- **`proxy_token()` is now section-aware.** It previously only checked the token *format*
  (a `ranbval.*` value), so it would happily return a token for a key declared under
  `[secrets]` or `[public]`. It now refuses those — a `[secrets]` key must be read with
  `decrypt_key().use()`, a `[public]` key with `public()` — which catches misuse such as
  passing a `[secrets]` database password to the HTTP proxy. `[proxy]` keys and unlabelled
  `ranbval.*` tokens are still accepted. This makes all three accessors own their section
  (`public()` → `[public]`, `decrypt_key()` → `[secrets]`, `proxy_token()` → `[proxy]`).

---

## [2.1.0] - 2026-07-09

### Added
- **`[proxy]` section** — a third `.ranbval` section for secrets whose plaintext must **never**
  reach the client. `decrypt_key()` **refuses** a `[proxy]` key (`RanbvalConfigError`, code
  `proxy_only`); the value is usable only via `proxy_request()`, where the real key is decrypted
  and injected on Ranbval's server. New helpers `proxy_token("NAME")` (returns the raw encrypted
  token to pass to the proxy) and `is_proxy("NAME")`. Header aliases: `[proxy]` / `[proxy-only]` /
  `[sealed]`. `public()` also refuses `[proxy]` keys, and `load_ranbval()` warns if a `[proxy]`
  value is plaintext.

  The three sections now express a visibility ladder:
  - `[public]` — plaintext, anyone may read (e.g. shown in a UI).
  - `[secrets]` — encrypted at rest; the app *can* decrypt and view/use it at runtime.
  - `[proxy]` — encrypted; plaintext never reaches the client (HTTP API keys, Stripe keys).

  Combine `[proxy]` with **not shipping `RANBVAL_PROJECT_SECRET` to that client** and it is
  cryptographically impossible for that environment to produce the plaintext at all.

  Fully backward compatible — sections remain optional.

---

## [2.0.0] - 2026-07-08

### Removed (breaking)
- **`secure_client()` and `build_secure_client()` are removed.** They implicitly assumed an
  OpenAI/Anthropic-shaped SDK (a class with an `api_key=` constructor kwarg plus a nested method
  to patch), so they did not fit providers with a different shape — e.g. Google Gemini
  (`genai.configure(api_key=...)`), AWS Bedrock (`boto3`), Vertex, and others. Ranbval is a
  **provider-agnostic secret manager**: decrypt the key and pass it wherever the provider wants it.

  **Migration** — replace the wrapper with a direct decrypt at the call site:

  ```python
  # before
  client = secure_client(openai.OpenAI, env_var="OPENAI_API_KEY", key_kwarg="api_key")

  # after — works for OpenAI, Anthropic, Gemini, Bedrock, raw HTTP, anything
  client = openai.OpenAI(api_key=decrypt_key("OPENAI_API_KEY").use())
  ```

  Usage is still auto-reported by `decrypt_key()`; nothing about telemetry or the security model
  changes. The `integrations/factory.py` and `integrations/universal.py` modules were deleted;
  the server-side `proxy_request()` / `aproxy_request()` remain.

---

## [1.4.1] - 2026-07-08

Hardening, privacy, and maintainability pass. **No breaking public-API changes** — every
`from ranbval_sdk import …` still works. One documented behaviour is now correct:
`build_secure_client(..., env_var=..., key_kwarg=...)` matches the README (the parameters were
previously named `env_var_name` and only worked positionally).

### Added
- **`[public]` / `[secrets]` sections** in `.ranbval` — declare unencrypted config
  (`DATABASE_URL`, `CORS_ORIGINS`, `PORT`, …) separately from encrypted vault tokens. New
  `public(name)` / `public_config()` / `is_public(name)` accessors return plaintext only and
  refuse to hand back a declared secret or a `ranbval.*` token. The same guarded access is
  available on the `Vault` / `env` object as `env.public(name)` / `env.public_config()`, so a
  secret can never be read through a public path on any access surface. `load_ranbval()` warns
  when a value contradicts its section. Fully backward compatible — sections are optional and
  flat files behave exactly as before. New `config/manifest.py`.
- **Telemetry privacy switches** — `RANBVAL_TELEMETRY_DISABLED=1` turns off all usage
  reporting; `RANBVAL_TELEMETRY_IDENTITY=1` opts in to sending `git config user.email`
  (now **off by default** — PII is not collected unless enabled). New `telemetry/settings.py`.
- **Structured errors** — `RanbvalError` now carries a machine-readable `.code` and a
  `.context` dict for logging/metrics without parsing message strings.
- **Repo-policy caching** — the per-decrypt allowlist fetch is cached per `(host, salt)` for
  60s, so hot decrypt loops no longer make one blocking HTTP round-trip per call.

### Changed
- **Pure-Python packaging** — removed the stale Cython build hook (`build.py`) and the
  `Cython`/`setuptools` build requirements. The SDK ships as a universal wheel + sdist that
  installs on any platform (previously only a macOS-arm64 wheel built, and it referenced a
  `crypto.py` that no longer exists). Obfuscation was never a security control.
- **`SecretString` refuses serialization** — `pickle`, `copy`, and `deepcopy` now raise
  `TypeError`, closing the real accidental-leak paths (error reporters like Sentry pickling
  local variables, celery/multiprocessing pickling task args, disk/redis caches). `.use()`
  values keep working inside SDKs (copy allowed for the immutable str; only pickle refused).
  Docstrings/README rewritten to describe the guarantees **honestly** — masking blocks
  accidental exposure; it is not a defense against deliberate reveals or process-memory
  attackers, and memory zeroing/`mlock` are best-effort, not guarantees.
- **`load_ranbval()` no longer patches global builtins by default** — the `print` /
  `sys.stdout.write` output guards are now opt-in via `load_ranbval(guard_stdout=True)`.
  `SecretString` still masks itself via `__str__`/`__repr__`. Removed the fragile
  frame-inspection f-string detection.
- **Honest crypto errors** — replaced pseudo-technical messages ("packet fragmentation",
  "signature matrix") and the hard-coded `"ahsan"` label check with clear, actionable
  messages. The token `<label>` is now treated as an opaque tag (so labels like `stripe`
  work), and token parsing/TTL handling is factored into small tested helpers.
- **Auto-patched SDK telemetry** now flows through the same adaptive sampler as
  `decrypt_key()` instead of spawning a thread + POST on every call.
- **Deprecation via `warnings.warn`** — `RANBVAL_VAULT_SECRET` deprecation uses
  `DeprecationWarning` instead of printing to stderr.
- **Consistent style** — modern `X | None` type hints, sorted imports, and `ruff` + `mypy`
  configuration added to `pyproject.toml`. `MissingKeyError` no longer double-quotes its
  message (the classic `KeyError.__str__` gotcha).

---

## [1.3.0] - 2026-07-08

Internal reorganization for a stricter separation of concerns — **gather → shape → send**,
and **policy** split out from **crypto**. **The public API is unchanged**; every
`from ranbval_sdk import …` import works exactly as before, and the old submodule paths keep
resolving via re-export shims.

### Added
- **`serializers/` package** — one module per wire shape, each a pure *shaping* function
  (no I/O, no data-gathering): `telemetry.py` (`build_telemetry_payload` +
  `build_security_metadata`), `proxy.py` (`build_proxy_payload`), `token.py`
  (`salt_from_ranbval_token`), and `audit.py` (`AuditEntry` + `build_audit_entry`).
- **`policy/` package** — provenance & access enforcement as its own concern. The git-remote
  allowlist check moved here (`policy/repo.py`); `crypto/` now contains cryptography only.
- **`telemetry/context.py`** — `collect_client_context()` gathers the client runtime signals
  (SDK/Python version, git branch & email, timezone, hashed device id) that feed a telemetry
  event. Separated from the serializer, which now only shapes the values it is given.
- **`config/declarative.py`** — the class-based access API (`Secret`, `SecretConfig`) split out
  from the imperative `Vault` / `inject` / `secrets` in `config/access.py`.
- **`_internal/logging.py`** — the opt-in `RANBVAL_TELEMETRY_DEBUG` stderr diagnostic moved out
  of `_internal/defaults.py`, which is now constants-only.

### Changed
- `telemetry/client.py` and `integrations/proxy.py` now delegate payload construction to the
  `serializers/` builders instead of inlining the request dicts.

### Notes
- Back-compatible re-exports are in place: `ranbval_sdk.crypto.repo_policy`,
  `ranbval_sdk.crypto.audit.AuditEntry`, `ranbval_sdk.telemetry.salt_from_ranbval_token`,
  `ranbval_sdk.telemetry.client.salt_from_ranbval_token`, and
  `ranbval_sdk._internal.defaults.warn_telemetry_send_failed` all still import.
- No change to crypto behavior, the `.ranbval` wire format, the telemetry/proxy payloads
  (byte-identical), or the `reveal=False` sealing defaults.

---

## [1.2.0] - 2026-07-07

Policy is now **server-controlled and always-on** — the client can no longer skip
enforcement or telemetry, and usage reports itself automatically.

### Changed (behavioral)
- **Repo allowlist enforcement can no longer be skipped.** The `RANBVAL_SKIP_REPO_CHECK`
  env var is gone; the allowlist is enforced purely by the control plane's policy response.
  Decrypting a vault token now requires the control plane to be reachable (fail-closed).
- **Telemetry can no longer be disabled.** The `RANBVAL_TELEMETRY=0/off` opt-out is gone;
  usage is always reported to the Live Monitor.
- **Telemetry is now automatic and adaptively aggregated.** `decrypt_key()` reports usage to
  the Live Monitor on its own — you no longer write a separate `emit_telemetry()` call. To stay
  cheap under hot loops, the **first use of a credential is sent immediately**, and **repeats
  are counted locally and flushed as one aggregated event (~30s + at exit)** carrying an
  `item_count` weight. `emit_telemetry()` remains available for richer custom events.

  > **Control plane:** telemetry payloads now include `item_count` — the number of actual uses an
  > event represents. Multiply by it (default `1`) when tallying usage so sampled/aggregated
  > events reconstruct the true totals.
- **Richer telemetry fields.** Each event now also carries: `roundtrip_ms` (decrypt latency),
  `git_email` (developer identity), `timezone` (coarse geo hint; precise geo is derived
  server-side from the IP), and `device_id` (a **hashed**, non-reversible device fingerprint —
  the raw MAC is never sent). `device_id` is the key signal for **leak detection**: the control
  plane can flag the same credential used from multiple distinct devices/IPs.

### Migration
- Remove any `RANBVAL_SKIP_REPO_CHECK` / `RANBVAL_TELEMETRY` entries from `.ranbval` files
  and CI config — they are silently ignored. Manage the repo allowlist from the dashboard.

---

## [1.1.0] - 2026-07-07

Internal reorganization and professionalization. **The public API is unchanged** — every
`from ranbval_sdk import …` import works exactly as before.

### Added
- Concern-based subpackages: `config/` (`loader` + `access`), `crypto/` (`cipher`,
  `secret_string`, `audit`, `repo_policy`), `telemetry/` (`client` + `decorators`),
  `integrations/` (`factory`, `universal`, `proxy`), and internal `_internal/`
  (`defaults`, `transport`). Only `__init__.py`, `exceptions.py`, and `py.typed` sit at the
  package root.
- Unified exception hierarchy in `ranbval_sdk.exceptions`: a `RanbvalError` base with
  `RanbvalDecryptError`, `RanbvalConfigError`, `MissingKeyError`, `RepoNotAllowedError`,
  `RepoPolicyError`, and `ProxyError`. Each also subclasses the built-in it replaces
  (`ValueError` / `KeyError` / `PermissionError` / `RuntimeError`), so existing
  `except ValueError` / `except PermissionError` code keeps catching.
- `py.typed` marker — the package now ships type information (PEP 561).
- `__version__` attribute on the package.

### Changed
- Split the 528-line `dot_ranbval.py` into `config/loader.py` (file loading) and
  `config/access.py` (`Vault`, `inject`, `secrets`, `Secret`). `crypto.py`,
  `secret_string.py`, `audit.py`, `telemetry.py`, `http_tls.py`, `repo_policy.py`, and
  `proxy.py` moved into their concern subpackages.
- Tests moved to `tests/`; the manual integration script moved to `scripts/`.
- `crypto.cipher.PBKDF2_ITERATIONS` extracted as a named constant (value unchanged at
  100,000 — see Notes).

### Notes
- Deep internal module paths (e.g. `ranbval_sdk.dot_ranbval`, `ranbval_sdk.http_tls`,
  `ranbval_sdk.secret_string`) were part of the internal layout, not the public API, and are
  no longer importable — use the top-level `from ranbval_sdk import …` exports (and
  `from ranbval_sdk.telemetry import salt_from_ranbval_token`, `from ranbval_sdk.crypto import …`,
  which still resolve via the subpackages).
- PBKDF2 iterations remain **100,000**, kept in lock-step with the Ranbval control plane and
  the Node SDK. Raising toward the OWASP-2023 figure (600,000) requires a coordinated
  versioned-token migration across the server and both SDKs — tracked as future work.

---

## [0.9.0] - 2024-12-01

### Added
- `decrypt_key(env_var)` — single-call convenience wrapper: reads the env var, reads `RANBVAL_PROJECT_SECRET`, and returns a `SecretString`. Recommended pattern for new integrations.
- `get_audit_log()` and `clear_audit_log()` — in-process audit log for every decrypt and telemetry event. Useful for testing and compliance verification.
- `find_ranbval_file()`, `find_ranbval_directory()`, `resolve_ranbval_mode()` — lower-level discovery helpers now part of the public API.

### Changed
- `RANBVAL_PROJECT_SECRET` is now the canonical env var name (replaces `RANBVAL_VAULT_SECRET`).
- `.ranbval.example` updated to use `RANBVAL_PROJECT_SECRET`.

---

## [0.8.0] - 2024-10-15

### Added
- `proxy_request()` and `ProxyError` — route outbound HTTP requests through the Ranbval proxy with TLS verification.
- `RANBVAL_TELEMETRY_DEBUG` env var: set to `1` to print telemetry POST errors to stderr for easier CI debugging.

### Changed
- `emit_telemetry()` is now a silent no-op (instead of raising) when no `client_salt` can be resolved — safe to call unconditionally even with plain non-ranbval keys.

### Fixed
- Telemetry daemon thread was not marked as daemon in all code paths, which could delay process exit.

---

## [0.7.0] - 2024-09-01

### Added
- `build_secure_client()` — returns a subclass of the wrapped SDK class instead of an instance, for use with factories and dependency injection containers.
- `certifi` pinned as an explicit dependency to ensure up-to-date CA bundles on all platforms.

### Changed
- `secure_client()` now accepts `method_path_to_patch` as a dotted string (e.g. `"chat.completions.create"`) for deeper method trees.

---

## [0.6.0] - 2024-07-20

### Added
- `secure_client()` — wrap any third-party SDK class to auto-decrypt the key kwarg and fire `emit_telemetry()` after each call.
- `integrations/` subpackage for SDK wrapper logic.

### Changed
- `http_tls.py` refactored into a standalone module; all outbound requests now go through a single TLS-verified session using `certifi`.

---

## [0.5.0] - 2024-06-10

### Added
- Repo allowlist enforcement in `safe_decrypt()`: the SDK reads the local git remote URL and checks it against the project's allowed repos via `GET /api/public/repo-policy`.
- `RANBVAL_SKIP_REPO_CHECK=1` bypass flag for CI environments and local development without a git remote.

### Changed
- `safe_decrypt()` now raises `PermissionError` (instead of a generic `ValueError`) when the repo check fails.

---

## [0.4.0] - 2024-04-28

### Added
- `emit_telemetry()` — POST usage events (model, token counts, event kind) to the Ranbval Live Monitor.
- `background=True` parameter fires telemetry in a daemon thread so it does not block the main call path.
- `RANBVAL_TELEMETRY=0` env var to disable all telemetry POSTs.

---

## [0.3.0] - 2024-03-15

### Added
- `SecretString` — string wrapper that blocks `__str__`, `__repr__`, and `__format__`, making it impossible to accidentally print a secret to stdout or logs. Value accessible only via `.use()`.
- `safe_decrypt()` now always returns a `SecretString` instead of a plain `str`.

### Changed
- Minimum Python version set to 3.10 (match `match`/`case` usage in internal parsing).

---

## [0.2.0] - 2024-02-01

### Added
- `safe_decrypt(token, secret)` — AES-256-GCM decryption with PBKDF2 key derivation. Parses `ranbval.<salt>.<blob>.<label>` token format.
- `get_project_key()` — reads `RANBVAL_PROJECT_SECRET` from `os.environ` with a clear error message if missing.
- `cryptography >= 42.0.0` added as a required dependency.

---

## [0.1.0] - 2024-01-10

### Added
- `load_ranbval()` — discovers and merges layered `.ranbval*` files into `os.environ`. Supports base, mode, local, and mode-local layers.
- Mode resolution from `load_ranbval(mode=...)`, `RANBVAL_ENV`, `ENVIRONMENT`, `ENV`, with `development` as default.
- `RANBVAL_HOST` env var for pointing the SDK at a self-hosted or staging API instance.
- Initial package structure: `src/ranbval_sdk/` layout, `pyproject.toml` with Poetry, `build.py` for Cython compilation.
