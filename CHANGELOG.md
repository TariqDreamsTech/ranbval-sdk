# Changelog

All notable changes to `ranbval-sdk` are documented here.

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
