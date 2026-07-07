[![PyPI](https://img.shields.io/pypi/v/ranbval-sdk)](https://pypi.org/project/ranbval-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/ranbval-sdk)](https://pypi.org/project/ranbval-sdk/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

# Ranbval SDK `v1.0.1`

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
| Keys copied and shared freely | Repo allowlist — if a repo is not authorized, the key cannot decrypt |
| No idea who used what, when | Live Monitor — every usage logged with machine, repo, model, tokens |
| `load_dotenv()` scattered everywhere | One call: `load_ranbval()` — layered, mode-aware, zero side effects on import |

---

## Quick Start

```python
from ranbval_sdk import load_ranbval, decrypt_key
import os, openai

# 1. Load encrypted config from .ranbval files (no network, no decryption)
load_ranbval()

# 2. Decrypt a vault token — returns a SecretString, never printable
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
| `safe_decrypt()` | Decrypts a vault token string → `SecretString` |
| `decrypt_key()` | Reads an env var and decrypts it in one call |
| `SecretString` | Wrapper that blocks all display paths — value only via `.use()` |
| `secure_client()` | Wrap a third-party SDK class for auto-decrypt + telemetry |
| `build_secure_client()` | Same as `secure_client()` but returns a subclass instead of an instance |
| `proxy_request()` | Route an HTTP request through the Ranbval proxy |
| `emit_telemetry()` | POST a usage event to the Ranbval Live Monitor |
| `get_audit_log()` | Return the in-process audit log list |
| `clear_audit_log()` | Clear the in-process audit log |
| `get_project_key()` | Read `RANBVAL_PROJECT_SECRET` from env |
| `find_ranbval_file()` | Locate the nearest `.ranbval*` file on disk |
| `find_ranbval_directory()` | Locate the config root directory |
| `resolve_ranbval_mode()` | Determine the active mode from env/args |

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
- `PermissionError` — this Git repo is not in the allowed list
- `ValueError` — wrong project secret or corrupted token

**Bypass flag (dev/CI only):**

```bash
RANBVAL_SKIP_REPO_CHECK=1   # skip git remote allowlist check
```

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

This is the recommended pattern for most applications — it reduces boilerplate and keeps the project secret out of your application code.

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

Posts a usage event to the Ranbval Live Monitor. Call it after your API request so the dashboard can track every usage against the correct vault credential.

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
| `background` | `bool` | `True` = fire-and-forget in a daemon thread |
| `host_url` | `str` | Override `RANBVAL_HOST` for this call |

If no `client_salt` can be resolved the call is a silent no-op — safe to call even with plain (non-ranbval) keys.

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

## `.ranbval` File Format

`.ranbval` files follow the same `KEY=VALUE` format as `.env` files. Lines starting with `#` are comments. Blank lines are ignored.

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
| `RANBVAL_SKIP_REPO_CHECK` | `0` | `1` = skip git remote allowlist check |
| `RANBVAL_TELEMETRY` | `on` | `0` / `false` = disable telemetry POSTs |
| `RANBVAL_TELEMETRY_DEBUG` | `0` | `1` = print telemetry errors to stderr |

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
    │       ├── 1. Repo allowlist check  →  GET /api/public/repo-policy?client_salt=...
    │       └── 2. AES-256-GCM decrypt   →  SecretString (value sealed, never printable)
    │
    ├── secret.use()            Only access point — pass directly to SDK / headers
    │
    └── emit_telemetry()        POST /api/telemetry → Ranbval Live Monitor
```

AES-256-GCM encryption with PBKDF2 key derivation. The project secret never leaves your environment — decryption happens entirely on your machine.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Links

- PyPI: [pypi.org/project/ranbval-sdk](https://pypi.org/project/ranbval-sdk/)
- Dashboard: [ranbval.com](https://www.ranbval.com)
- API docs: [api.ranbval.com/docs](https://api.ranbval.com/docs)
- Repository: [github.com/TariqDreamsTech/ranbval-sdk](https://github.com/TariqDreamsTech/ranbval-sdk)
