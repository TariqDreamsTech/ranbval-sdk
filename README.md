[![PyPI](https://img.shields.io/pypi/v/ranbval-sdk)](https://pypi.org/project/ranbval-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/ranbval-sdk)](https://pypi.org/project/ranbval-sdk/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

# Ranbval SDK `v1.4.0`

Keep API secrets out of plaintext config. Encrypt them in the Ranbval dashboard, store encrypted tokens in `.ranbval` files, decrypt only at runtime — AES-256-GCM with PBKDF2 key derivation, no plaintext ever touches source control.

```bash
pip install ranbval-sdk
```

---

## Why Ranbval Exists

With so many LLM APIs and third-party services in use today, managing secrets has become a real operational problem. Someone shares an API key, it gets copied, forwarded, and committed — and suddenly the bill arrives with no way to trace which repo or person burned the tokens.

| Problem | Ranbval Solution |
|---------|-----------------|
| API keys committed to Git | Encrypted `.ranbval*` files — plaintext never touches source control |
| Keys copied and shared freely | Repo allowlist — enforced by the control plane; an unauthorized repo cannot decrypt, and it can't be skipped from the client |
| No idea who used what, when | Live Monitor — every decrypt is reported automatically with machine, repo, model, tokens |
| `load_dotenv()` scattered everywhere | One call: `load_ranbval()` — layered, mode-aware, zero side effects on import |

---

## Quick Start

```python
from ranbval_sdk import load_ranbval, decrypt_key
import os, openai

# 1. Load encrypted config from .ranbval files (no network, no decryption)
load_ranbval()

# 2. Decrypt a vault token — returns a SecretString, never printable.
#    This also auto-reports the usage to your Live Monitor (no extra code).
api_key = decrypt_key("OPENAI_API_KEY")

# 3. Pass directly to the SDK — value is never exposed in logs or prints
client = openai.OpenAI(api_key=api_key.use())

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}],
)
```

`.ranbval.local` (never commit this file):
```bash
RANBVAL_PROJECT_SECRET=your_dashboard_project_secret
OPENAI_API_KEY=ranbval.4ii0a022aa.p1GOZ...ahsan
```

---

## Module Reference

| Symbol | Description |
|--------|-------------|
| `load_ranbval()` | Merges layered `.ranbval*` files into `os.environ` |
| `public()` | Read a plaintext (unencrypted) config value — never decrypts |
| `public_config()` | Dict of every key declared under `[public]` |
| `safe_decrypt()` | Decrypts a vault token string → `SecretString` |
| `decrypt_key()` | Reads an env var and decrypts it in one call |
| `SecretString` | Wrapper that blocks all display paths — value only via `.use()` |
| `secure_client()` | Wrap a third-party SDK class for auto-decrypt + telemetry |
| `build_secure_client()` | Same as `secure_client()` but returns a subclass instead of an instance |
| `proxy_request()` | Route an HTTP request through the Ranbval proxy |
| `emit_telemetry()` | Record a **custom** usage event (basic usage is auto-reported on every `decrypt_key()`) |
| `get_audit_log()` | Return the in-process audit log list |
| `clear_audit_log()` | Clear the in-process audit log |
| `get_project_key()` | Read `RANBVAL_PROJECT_SECRET` from env |
| `find_ranbval_file()` | Locate the nearest `.ranbval*` file on disk |
| `find_ranbval_directory()` | Locate the config root directory |
| `resolve_ranbval_mode()` | Determine the active mode from env/args |

---

## Package Layout

Everything is organized by concern. You only import from the top level
(`from ranbval_sdk import …`); the table shows where each piece lives.

```
ranbval_sdk/
├── __init__.py          # the public API (re-exports everything below)
├── exceptions.py        # RanbvalError hierarchy
├── py.typed             # ships type information (PEP 561)
├── config/              # your .ranbval configuration surface
│   ├── loader.py        #   load_ranbval, find_*, resolve_ranbval_mode, get_project_key
│   ├── access.py        #   imperative access — Vault, env, inject, secrets, iter_secrets
│   └── declarative.py   #   class-based access — Secret, SecretConfig
├── crypto/              # cryptography & sealed secrets (only crypto lives here)
│   ├── cipher.py        #   AES-256-GCM decrypt + project-secret resolution
│   ├── secret_string.py #   SecretString — the sealed, never-printable value
│   └── audit.py         #   in-memory log of every .use()
├── policy/              # provenance & access policy (the decrypt gate)
│   └── repo.py          #   git-remote allowlist enforcement (server-controlled)
├── serializers/         # wire (de)serializers — one module per payload shape
│   ├── telemetry.py     #   /api/telemetry body + security metadata
│   ├── proxy.py         #   /api/execute request body
│   ├── token.py         #   parse ranbval.<salt>.<blob>.<label>
│   └── audit.py         #   AuditEntry record shape
├── telemetry/           # usage reporting to the Live Monitor
│   ├── client.py        #   emit_telemetry / aemit_telemetry (I/O)
│   ├── context.py       #   collect_client_context — gather client runtime signals
│   ├── sampling.py      #   adaptive aggregation (first-seen send, repeats counted)
│   └── decorators.py    #   @track / tracked()
├── integrations/        # calling your vendor SDKs safely
│   ├── factory.py       #   secure_client
│   ├── universal.py     #   build_secure_client
│   └── proxy.py         #   proxy_request / aproxy_request (key never leaves the server)
└── _internal/           # private cross-cutting utilities
    ├── defaults.py      #   shared constants
    ├── logging.py       #   opt-in stderr diagnostics (RANBVAL_TELEMETRY_DEBUG)
    └── transport.py     #   HTTPS via urllib + certifi
```

> Layered by responsibility: **gather** (`telemetry.context`) → **shape** (`serializers/`)
> → **send** (`telemetry.client`). Policy enforcement (`policy/`) is separate from
> cryptography (`crypto/`). You still only import from the top level.

---

## Function Reference

### `load_ranbval()`

Loads configuration from `.ranbval*` files into `os.environ`. No network calls, no decryption, zero side effects on import.

```python
from ranbval_sdk import load_ranbval

load_ranbval()                              # auto-discover from cwd upward
load_ranbval(mode="production")             # force a specific mode
load_ranbval(start="/path/to/project")      # start search from a custom directory
load_ranbval("/absolute/path/to/file")      # single file, skip layer discovery
load_ranbval(override=True)                 # file values overwrite existing os.environ
```

**How it finds files**

Walks from `cwd` upward until it finds a directory containing `.ranbval` or any `.ranbval.*` file. That becomes the config root.

**Merge order** (later file wins for duplicate keys):

```
.ranbval                   ← shared base
.ranbval.{mode}            ← e.g. .ranbval.production
.ranbval.local             ← machine-only, add to .gitignore
.ranbval.{mode}.local      ← highest priority
```

**Mode resolution order:**
1. `load_ranbval(mode="...")` explicit argument
2. `RANBVAL_ENV` environment variable
3. `ENVIRONMENT` environment variable
4. `ENV` environment variable
5. Default: `development`

**Returns:** `True` if at least one file was read, `False` if none found.

**Example `.ranbval` file:**

```bash
# Plain values — safe to commit
APP_NAME=my-app
DATABASE_URL=postgresql://localhost/mydb

# Encrypted vault token — generated in the Ranbval dashboard
OPENAI_API_KEY=ranbval.4ii0a022aa.p1GOZ...ahsan
```

---

### `safe_decrypt()`

Decrypts a `ranbval.*` vault token string using AES-256-GCM with PBKDF2 key derivation.

```python
from ranbval_sdk import load_ranbval, safe_decrypt
import os

load_ranbval()

secret = safe_decrypt(
    os.environ["OPENAI_API_KEY"],          # the ranbval.* token string
    os.environ["RANBVAL_PROJECT_SECRET"],  # your project secret
)

client = openai.OpenAI(api_key=secret.use())
```

**Returns:** a [`SecretString`](#secretstring) — the decrypted value is never accessible via print, str, repr, f-strings, or logs.

```python
print(secret)        # → [ranbval:secret]
str(secret)          # → [ranbval:secret]
f"key={secret}"      # → key=[ranbval:secret]
repr(secret)         # → SecretString(***)
len(secret)          # → 164  (safe — reveals only length)

# Only correct usage:
client = openai.OpenAI(api_key=secret.use())
headers = {"Authorization": f"Bearer {secret.use()}"}
```

**Raises:**
- `RepoNotAllowedError` (a `PermissionError`) — this Git repo is not in the allowed list
- `RanbvalDecryptError` (a `ValueError`) — wrong project secret or corrupted token

The repo allowlist is **enforced by the control plane and cannot be skipped on the client** —
there is no local bypass flag. Manage the allowed repositories from the Ranbval dashboard.

---

### `decrypt_key()`

Convenience wrapper: reads an env var and decrypts it in one call. The project secret is read from `RANBVAL_PROJECT_SECRET` automatically.

```python
from ranbval_sdk import load_ranbval, decrypt_key

load_ranbval()

# Reads os.environ["OPENAI_API_KEY"] and os.environ["RANBVAL_PROJECT_SECRET"]
api_key = decrypt_key("OPENAI_API_KEY")

client = openai.OpenAI(api_key=api_key.use())
```

This is the recommended pattern for most applications — it reduces boilerplate and keeps the project secret out of your application code. Each call also **auto-reports the usage** to the Live Monitor.

**Raises:** `RanbvalConfigError` (env var not set / no project secret), `RanbvalDecryptError` (wrong secret or corrupt token), `RepoNotAllowedError` (repo not in the allowlist) — all subclasses of `RanbvalError`, and each also a subclass of the built-in it replaces (`ValueError` / `PermissionError`).

---

### `SecretString`

A string wrapper that makes it impossible to accidentally expose a secret through print, logging, f-strings, or repr.

```python
from ranbval_sdk import SecretString

# Created automatically by safe_decrypt() / decrypt_key()
# — but you can also wrap your own values:
secret = SecretString("sk-proj-super-secret-key", label="openai")

print(secret)           # [ranbval:secret]
repr(secret)            # SecretString(***)
f"key={secret}"         # key=[ranbval:secret]
str(secret)             # [ranbval:secret]
len(secret)             # 26  ← safe

# Only way to get the real value:
real_value = secret.use()
```

**Why this matters:**

```python
# Old way — key leaks in logs/stdout
api_key = os.environ["OPENAI_KEY"]
print(f"Using key: {api_key}")           # key printed to console/logs

# Ranbval way — impossible to leak accidentally
secret = decrypt_key("OPENAI_KEY")
print(f"Using key: {secret}")            # → Using key: [ranbval:secret]
```

| Method / Property | Description |
|-------------------|-------------|
| `.use()` | Returns the raw string — the only access point |
| `len(secret)` | Length of the secret (safe to log) |
| `.label` | Optional name set at creation |
| `==` | Compares two `SecretString` values securely |

---

### `secure_client()` / `build_secure_client()`

Wrap a third-party SDK class so it auto-decrypts the key and fires telemetry on every call.

```python
from ranbval_sdk import load_ranbval, secure_client
import openai

load_ranbval()

# Returns an openai.OpenAI instance with auto-decrypt + telemetry
client = secure_client(
    openai.OpenAI,
    env_var="OPENAI_API_KEY",
    key_kwarg="api_key",
    method_path_to_patch="chat.completions.create",
)

# Use exactly like openai.OpenAI — telemetry fires automatically
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}],
)
```

`build_secure_client()` returns a subclass instead of an instance — use when you need to instantiate multiple times or pass to a factory:

```python
from ranbval_sdk import build_secure_client
import anthropic

SecureAnthropic = build_secure_client(
    anthropic.Anthropic,
    env_var="ANTHROPIC_API_KEY",
    key_kwarg="api_key",
)

client = SecureAnthropic()
```

---

### `emit_telemetry()`

Posts a usage event to the Ranbval Live Monitor.

> **You usually don't need to call this.** `decrypt_key()` already reports usage to the Live
> Monitor automatically — and does it efficiently: the **first use of a credential is sent
> immediately**, then **repeats are counted locally and flushed as one aggregated event**
> (~every 30s and at process exit) carrying an `item_count` weight. So a hot loop that decrypts
> the same key 10,000× produces a handful of events, not 10,000 POSTs. Call `emit_telemetry()`
> only to record a *richer custom event* — e.g. model name and token counts after an LLM call.

```python
from ranbval_sdk import emit_telemetry

emit_telemetry(
    vault_token_env="OPENAI_API_KEY",   # env var holding a ranbval.* token
    model_used="gpt-4o",
    prompt_tokens=512,
    completion_tokens=128,
    event_kind="llm.chat",
    background=True,                    # non-blocking daemon thread
)
```

Or pass the salt directly if you have it:

```python
emit_telemetry(
    client_salt="4ii0a022aa",
    model_used="stripe.charge",
    background=True,
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `vault_token_env` | `str` | Env var name holding a `ranbval.*` token — salt extracted automatically |
| `client_salt` | `str` | Use instead of `vault_token_env` if you already have the salt |
| `model_used` | `str` | Label shown in the dashboard (e.g. `"gpt-4o"`, `"stripe.charge"`) |
| `prompt_tokens` | `int` | Input tokens (0 if not an LLM call) |
| `completion_tokens` | `int` | Output tokens (0 if not an LLM call) |
| `event_kind` | `str` | Event category (e.g. `"llm.chat"`, `"custom.request"`) |
| `item_count` | `int` | Aggregation weight — how many actual uses this event represents (default `1`) |
| `roundtrip_ms` | `float` | Client-measured decrypt/round-trip latency, if you want to report it |
| `background` | `bool` | `True` = fire-and-forget in a daemon thread |
| `host_url` | `str` | Override `RANBVAL_HOST` for this call |

If no `client_salt` can be resolved the call is a silent no-op — safe to call even with plain (non-ranbval) keys.

**What each event sends.** Only a non-reversible token salt (never the plaintext secret) plus operational
metadata: SDK/Python version and platform, transport scheme, git branch, a coarse `timezone` geo hint,
decrypt latency, and a **hashed, non-reversible `device_id`** (a truncated SHA-256 of the machine ID —
the raw MAC is never sent). The `device_id` is the signal the control plane uses for **leak detection**:
the same credential appearing on multiple distinct devices/IPs raises an alert in the Live Monitor.

**Privacy controls.**
- `git config user.email` (developer identity) is **not** sent by default. Set `RANBVAL_TELEMETRY_IDENTITY=1`
  to opt in to attaching it (useful for attributing usage to a person on a shared machine).
- Set `RANBVAL_TELEMETRY_DISABLED=1` to turn usage reporting **off** entirely — every telemetry path
  becomes a no-op. Decryption and the repo-allowlist check are unaffected.

---

### `proxy_request()`

Route an outbound HTTP request through the Ranbval secure proxy. The real API key is decrypted server-side and never returned to the caller. Raises `ProxyError` on failure.

```python
from ranbval_sdk import load_ranbval, proxy_request, ProxyError
import os

load_ranbval()

try:
    result = proxy_request(
        token=os.environ["OPENAI_API_KEY"],        # ranbval.* vault token
        target_url="https://api.openai.com/v1/chat/completions",
        method="POST",
        inject_as="bearer",                         # Authorization: Bearer <secret>
        body={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
    )
    print(result["status"])   # HTTP status from the target
    print(result["body"])     # parsed JSON response
except ProxyError as e:
    print(f"Proxy failed: {e}")
```

**Inject modes:** `"bearer"` · `"basic"` · `"header:X-Api-Key"` · `"query:api_key"`

**Return value:** dict with keys `status` (int), `ok` (bool), `body` (parsed JSON or str), `headers` (dict).

`ProxyError` is raised when the proxy rejects the request (bad credentials, unknown token) or is unreachable.

---

### `get_audit_log()` / `clear_audit_log()`

The SDK records every decrypt and telemetry event in an in-process audit log. Useful for testing and compliance verification.

```python
from ranbval_sdk import load_ranbval, decrypt_key, get_audit_log, clear_audit_log

load_ranbval()
decrypt_key("OPENAI_API_KEY")

log = get_audit_log()
# [{"label": "OPENAI_API_KEY", "timestamp": 1716000000.0, "caller": "app.py:12"}]

clear_audit_log()
assert get_audit_log() == []
```

---

## Public vs. Secret Values

Not everything needs encryption. Values like `DATABASE_URL`, `CORS_ORIGINS`, or `PORT` are
plain config — you *want* them readable and committable. Encrypted vault tokens
(`OPENAI_API_KEY`, `STRIPE_SECRET_KEY`) are secrets. You can make that split explicit with
`[public]` and `[secrets]` section headers in `.ranbval`:

```bash
# .ranbval
RANBVAL_PROJECT_SECRET=ranbval-proj-xxx     # (or keep in .ranbval.local)

[public]                                     # plaintext — never decrypted
DATABASE_URL=postgresql://localhost/mydb
CORS_ORIGINS=https://app.example.com,https://admin.example.com
PORT=8000

[secrets]                                    # encrypted vault tokens
OPENAI_API_KEY=ranbval.4ii0a022aa.p1GO...ahsan
STRIPE_SECRET_KEY=ranbval.7cc2b931ff.xYz...stripe
```

```python
from ranbval_sdk import load_ranbval, public, public_config, decrypt_key

load_ranbval()

db      = public("DATABASE_URL")              # -> plain str (never a SecretString)
origins = public("CORS_ORIGINS").split(",")   # use directly in CORS config
cfg     = public_config()                     # -> {"DATABASE_URL": ..., "CORS_ORIGINS": ..., "PORT": ...}

api_key = decrypt_key("OPENAI_API_KEY")       # -> SecretString (decrypted on use)
```

**Rules & safety rails**

- **Fully backward compatible.** Sections are optional. A flat `.ranbval` (no headers) behaves
  exactly as before — `ranbval.*` values are auto-detected as secrets, everything else is plain.
- Keys **before any header** (or under an unrecognised header) stay *unlabelled* and keep the
  auto-detect behaviour.
- `public()` **refuses** to return a key declared under `[secrets]`, or any value that looks like
  an encrypted `ranbval.*` token — use `decrypt_key()` for those.
- `load_ranbval()` emits a `warning` if a `[public]` value is actually an encrypted token, or a
  `[secrets]` value is plaintext — catching copy/paste mistakes early.
- Header aliases: `[public]` = `[plain]` / `[plaintext]` / `[config]`; `[secrets]` = `[secret]` /
  `[vault]` / `[encrypted]`.

The same policy is available on the `Vault` / `env` object, so whichever access style you use,
a secret can never come out of a public path:

```python
from ranbval_sdk import env

env.public("DATABASE_URL")     # -> plain str
env.public("OPENAI_API_KEY")   # -> raises (declared [secrets]) — use env.reveal() / decrypt_key()
env.public_config()            # -> {name: plaintext} for every [public] key
```

---

## `.ranbval` File Format

`.ranbval` files follow the same `KEY=VALUE` format as `.env` files. Lines starting with `#` are comments. Blank lines are ignored. Optional `[public]` / `[secrets]` section headers group keys (see above).

```bash
# Plain value — stored and used as-is
APP_NAME=my-app
DATABASE_URL=postgresql://localhost/mydb

# Encrypted vault token — generated in the Ranbval dashboard
# Format: ranbval.<client_salt>.<aes-gcm-blob>.<label>
OPENAI_API_KEY=ranbval.4ii0a022aa.p1GOZtBx...3Kq==.ahsan
STRIPE_SECRET_KEY=ranbval.7cc2b931ff.xYZabc...Pq==.stripe
```

**Token format:** `ranbval.<client_salt>.<aes-gcm-blob>.<label>`

| Part | Description |
|------|-------------|
| `client_salt` | 10-character identifier used for session lookup and telemetry |
| `aes-gcm-blob` | IV + ciphertext, base64url-encoded |
| `label` | Human-readable tag shown in the dashboard |

---

## File Layout Example

```
my-project/
├── .ranbval                   ← shared defaults (safe to commit if no secrets)
├── .ranbval.production        ← production overrides (safe to commit)
├── .ranbval.local             ← machine secrets (gitignore this)
├── .ranbval.production.local  ← production + local overrides (gitignore this)
└── src/
    └── main.py
```

`.gitignore`:
```
.ranbval.local
.ranbval.*.local
```

`.ranbval` (committed, no secrets):
```bash
APP_NAME=my-app
RANBVAL_ENV=development
```

`.ranbval.production` (committed, encrypted tokens only):
```bash
OPENAI_API_KEY=ranbval.4ii0a022aa.p1GOZtBx...3Kq==.ahsan
```

`.ranbval.local` (never committed):
```bash
RANBVAL_PROJECT_SECRET=your_project_secret_from_dashboard
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RANBVAL_HOST` | `https://api.ranbval.com` | Ranbval API base URL |
| `RANBVAL_ENV` | `development` | Active mode for layered config |
| `RANBVAL_PROJECT_SECRET` | *(required)* | Project secret for `safe_decrypt()` / `decrypt_key()` |
| `RANBVAL_TELEMETRY_DEBUG` | `0` | `1` = print telemetry errors to stderr |
| `RANBVAL_TELEMETRY_DISABLED` | `0` | `1` = turn off all usage reporting (decryption still works) |
| `RANBVAL_TELEMETRY_IDENTITY` | `0` | `1` = opt in to sending `git config user.email` with events |

> **Repo-allowlist enforcement** is always on and controlled by the Ranbval dashboard — there is
> no client-side flag to skip it. **Usage telemetry** is on by default (so leak detection works),
> but you can turn it off with `RANBVAL_TELEMETRY_DISABLED=1`. `decrypt_key()` reports each use to
> the Live Monitor automatically; call `emit_telemetry()` only for richer custom events.

---

## n8n — HTTP Request + Telemetry

No Python needed. Use two **HTTP Request** nodes in your n8n workflow:

**Node 1** — Your API call (OpenAI, Stripe, etc.) via HTTPS.

**Node 2** — Telemetry log to Ranbval:

```
POST https://api.ranbval.com/api/telemetry
Content-Type: application/json

{
  "client_salt": "{{ $json.client_salt }}",
  "machine_name": "n8n",
  "repo_path": "{{ $workflow.name }}",
  "model_used": "openai.chat",
  "prompt_tokens": 0,
  "completion_tokens": 0,
  "security": {
    "event_kind": "custom.request",
    "transport": "https",
    "client_platform": "n8n"
  }
}
```

Extract `client_salt` from a `ranbval.*` token in a Code node:

```javascript
const token = $json.apiKey;
const salt = token.startsWith("ranbval.") ? token.split(".")[1] : null;
return [{ json: { client_salt: salt } }];
```

---

## Security Architecture

```
Your Code
    │
    ├── load_ranbval()          Reads .ranbval* files → os.environ (no network, no decrypt)
    │
    ├── decrypt_key("ENV_VAR")
    │       │
    │       ├── 1. Repo allowlist check  →  GET /api/public/repo-policy  (mandatory, server-controlled)
    │       ├── 2. AES-256-GCM decrypt   →  SecretString (value sealed, never printable)
    │       └── 3. Auto usage report     →  POST /api/telemetry → Live Monitor (automatic)
    │
    └── secret.use()            Only access point — pass directly to SDK / headers
```

AES-256-GCM encryption with PBKDF2 key derivation (100,000 iterations). The project secret
never leaves your environment — the decryption itself happens on your machine. The repo
allowlist check is always on and governed by the Ranbval control plane (no client-side bypass).
Usage reporting is on by default but can be disabled with `RANBVAL_TELEMETRY_DISABLED=1`.

**Network requirement:** because the allowlist is verified server-side on every decrypt,
resolving a vault token requires connectivity to the Ranbval control plane — the same as any
cloud secret manager (HashiCorp Vault, Doppler, AWS/GCP Secrets Manager). Plain (non-`ranbval.*`)
values in your `.ranbval` files resolve fully offline.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Links

- PyPI: [pypi.org/project/ranbval-sdk](https://pypi.org/project/ranbval-sdk/)
- Dashboard: [ranbval.com](https://www.ranbval.com)
- API docs: [api.ranbval.com/docs](https://api.ranbval.com/docs)
- Repository: [github.com/TariqDreamsTech/ranbval-sdk](https://github.com/TariqDreamsTech/ranbval-sdk)
