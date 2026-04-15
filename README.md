# 🔐 Ranbval SDK `v0.5.1`

> **Your secrets, your rules.**
> Stop committing plaintext API keys. Stop paying for other people's usage. Take back control.

```bash
pip install ranbval-sdk
```

[![PyPI](https://img.shields.io/pypi/v/ranbval-sdk)](https://pypi.org/project/ranbval-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/ranbval-sdk)](https://pypi.org/project/ranbval-sdk/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## 🧠 Why Ranbval Exists

With so many LLM APIs and services in the market today, **managing secrets has become a nightmare.**

Someone shares an API key → they share it with someone else → suddenly **the CEO is paying a massive unexpected bill** — and nobody knows which repo, which device, or which person burned the tokens.

**That is exactly why we built Ranbval.**

| Problem | Ranbval Solution |
|---------|-----------------|
| API keys committed to Git | Encrypted `.ranbval*` files — plaintext never touches source control |
| Keys copied and shared freely | **Repo allowlist** — if a repo is not authorized, the key cannot decrypt |
| No idea who used what, when | **Live Monitor** — every usage logged with machine, repo, model, tokens |
| Surprise bills from leaked keys | **Plan enforcement** — SDK checks subscription before every decrypt |
| `load_dotenv()` scattered everywhere | One call: `load_ranbval()` — layered, mode-aware, zero side effects on import |

**No more paying for other people's usage. Your secrets, your rules.**

---

## ⚡ Quick Start

```python
from ranbval_sdk import load_ranbval, safe_decrypt, emit_telemetry
import os

# 1. Load encrypted config from .ranbval files
load_ranbval()

# 2. Decrypt a vault token into a protected SecretString
secret = safe_decrypt(os.environ["MY_API_KEY"], os.environ["RANBVAL_VAULT_SECRET"])

# 3. Use it — value is NEVER visible in logs or prints
import openai
client = openai.OpenAI(api_key=secret.use())   # ← only access point

# 4. Log usage to Live Monitor
emit_telemetry(vault_token_env="MY_API_KEY", model_used="gpt-4o", background=True)
```

---

## 📦 What's Inside

| Module | What it does |
|--------|-------------|
| `load_ranbval()` | Merges layered `.ranbval*` files into `os.environ` |
| `safe_decrypt()` | Decrypts vault token → returns `SecretString` (never printable) |
| `SecretString` | Wrapper that blocks all display paths — value only via `.use()` |
| `assert_plan_active()` | Raises `BillingError` if subscription/trial is not valid |
| `fetch_billing_status()` | Inspect plan, limits, trial state for a vault session |
| `plan_limits()` | Get request/secret limits for the active plan |
| `emit_telemetry()` | POST usage log to Ranbval Live Monitor |
| `secure_client()` | Wrap a third-party SDK class for auto-decrypt + telemetry |

---

## 🗂️ Function Reference

---

### `load_ranbval()`

Loads configuration from `.ranbval*` files into `os.environ`. **No network calls. No decryption. Zero side effects on import.**

```python
from ranbval_sdk import load_ranbval

load_ranbval()                              # auto-discover from cwd upward
load_ranbval(mode="production")             # force a specific mode
load_ranbval(start="/path/to/project")      # start search from a custom directory
load_ranbval("/absolute/path/to/file")      # single file, skip layer discovery
load_ranbval(override=True)                 # file values overwrite existing os.environ
```

**How it finds files**

Walks from `cwd` upward until it finds a directory containing `.ranbval` or any `.ranbval.*` file. That becomes the **config root**.

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
# Plain values
APP_NAME=my-app
DATABASE_URL=postgresql://localhost/mydb

# Encrypted vault token (generated in the Ranbval dashboard)
OPENAI_API_KEY=ranbval.4ii0a022aa.p1GOZ...ahsan
```

---

### `safe_decrypt()`

Decrypts a `ranbval.*` vault token using AES-256-GCM with PBKDF2 key derivation.

Before decrypting it **automatically**:
1. ✅ Checks **repo allowlist** — is this Git repo allowed to use this key?
2. ✅ Checks **billing/plan** — does the vault owner have an active subscription?

```python
from ranbval_sdk import load_ranbval, safe_decrypt
import os

load_ranbval()

secret = safe_decrypt(
    os.environ["OPENAI_API_KEY"],       # the ranbval.* token
    os.environ["RANBVAL_VAULT_SECRET"], # your vault password
)
```

**Returns:** a [`SecretString`](#secretstring) — the decrypted value is **never** accessible via print, str, repr, f-strings, or logs.

```python
print(secret)        # → [ranbval:secret]
str(secret)          # → [ranbval:secret]
f"key={secret}"      # → key=[ranbval:secret]
repr(secret)         # → SecretString(***)
len(secret)          # → 164  (safe — reveals only length)

# ✅ Only correct usage:
client = openai.OpenAI(api_key=secret.use())
headers = {"Authorization": f"Bearer {secret.use()}"}
```

**Raises:**
- `BillingError` — no active subscription or trial expired
- `PermissionError` — this Git repo is not in the allowed list
- `ValueError` — wrong vault secret or corrupted token

**Bypass flags (dev/CI only):**

```bash
RANBVAL_SKIP_REPO_CHECK=1       # skip git remote allowlist check
RANBVAL_SKIP_BILLING_CHECK=1    # skip subscription/plan check
```

---

### `SecretString`

A string wrapper that **makes it impossible to accidentally expose a secret** through print, logging, f-strings, or repr.

```python
from ranbval_sdk import SecretString

# Created automatically by safe_decrypt() — but you can also wrap your own values:
secret = SecretString("sk-proj-super-secret-key", label="openai")

print(secret)           # [ranbval:secret]
repr(secret)            # SecretString(***)
f"key={secret}"         # key=[ranbval:secret]
str(secret)             # [ranbval:secret]
len(secret)             # 26  ← safe

# ✅ Only way to get the real value:
real_value = secret.use()
```

**Why this matters:**

```python
# ❌ Old way — key leaks in logs/stdout
api_key = os.environ["OPENAI_KEY"]       # plain string
print(f"Using key: {api_key}")           # 💀 key printed to console/logs

# ✅ Ranbval way — impossible to leak accidentally
secret = safe_decrypt(token, vault_secret)
print(f"Using key: {secret}")            # → Using key: [ranbval:secret]
```

**Properties:**
| Method/Property | Description |
|----------------|-------------|
| `.use()` | Returns the raw string — only access point |
| `len(secret)` | Length of the secret (safe) |
| `.label` | Optional name set at creation |
| `==` | Compares two SecretStrings by value (secure) |

---

### `assert_plan_active()`

Checks whether the vault owner has an active subscription or valid trial. Raises `BillingError` if not.

Called **automatically** inside `safe_decrypt()` — but you can also call it manually at app startup to fail fast.

```python
from ranbval_sdk import assert_plan_active, BillingError

salt = "4ii0a022aa"  # from ranbval.<salt>.<blob>.<label>

try:
    info = assert_plan_active(salt)
    print(f"Plan: {info['plan_key']} ({info['plan_name']})")
except BillingError as e:
    print(f"Access denied: {e}")
    # → Ranbval: your free trial has ended.
    #   Subscribe at https://www.ranbval.com to continue.
```

**What triggers a `BillingError`:**
- `vault_locked = True` (trial expired, no active subscription)
- No active subscription AND trial not running
- Trial expired

**Bypass for local dev:**
```bash
RANBVAL_SKIP_BILLING_CHECK=1
```

---

### `fetch_billing_status()`

Fetch full billing and plan information for a vault session — no auth token required, only the `client_salt`.

```python
from ranbval_sdk import fetch_billing_status

info = fetch_billing_status("4ii0a022aa")

print(info["plan_key"])              # "growth"
print(info["plan_name"])             # "Growth"
print(info["subscription_status"])  # "active"
print(info["has_active_subscription"])  # True
print(info["trial_active"])         # False
print(info["trial_expired"])        # False
print(info["vault_locked"])         # False
print(info["request_limit_month"])  # 100000
print(info["secrets_limit"])        # 50
```

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `plan_key` | `str\|None` | `starter` / `growth` / `pro` / `enterprise` |
| `plan_name` | `str\|None` | Human-readable plan name |
| `subscription_status` | `str\|None` | Stripe status: `active`, `trialing`, `past_due`, `canceled` |
| `has_active_subscription` | `bool` | True if subscription is active |
| `trial_active` | `bool` | True if free trial is currently running |
| `trial_expired` | `bool` | True if trial ended with no subscription |
| `trial_ends_at` | `str\|None` | ISO datetime when trial ends |
| `vault_locked` | `bool` | True = no access at all |
| `request_limit_month` | `int\|None` | Max API requests per month for this plan |
| `secrets_limit` | `int\|None` | Max secrets allowed for this plan |

**Raises:**
- `BillingError` — session not found (wrong salt or no matching project)
- `OSError` — network / TLS failure reaching the API

---

### `plan_limits()`

Lightweight shortcut — returns just the plan limits. **Never raises** (returns `{}` on any error).

```python
from ranbval_sdk import plan_limits

limits = plan_limits("4ii0a022aa")
# {
#   "plan_key": "growth",
#   "plan_name": "Growth",
#   "request_limit_month": 100000,
#   "secrets_limit": 50
# }
```

Use this when you want to **enforce limits in your own code** without crashing on billing errors:

```python
limits = plan_limits(salt)
if limits.get("request_limit_month") and usage > limits["request_limit_month"]:
    raise Exception("Monthly request limit reached — upgrade your Ranbval plan.")
```

---

### `emit_telemetry()`

Posts a usage event to the Ranbval Live Monitor. Call it **after** your API request so the dashboard tracks every usage against the correct vault credential.

```python
from ranbval_sdk import emit_telemetry

emit_telemetry(
    vault_token_env="OPENAI_API_KEY",   # env var holding a ranbval.* token
    model_used="gpt-4o",                # label shown in the dashboard
    prompt_tokens=512,
    completion_tokens=128,
    event_kind="llm.chat",
    background=True,                    # non-blocking (runs in a daemon thread)
)
```

**Or pass the salt directly:**

```python
emit_telemetry(
    client_salt="4ii0a022aa",
    model_used="my-service.v1",
    background=True,
)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `vault_token_env` | `str` | Env var name holding a `ranbval.*` token — salt extracted automatically |
| `client_salt` | `str` | Use instead of `vault_token_env` if you have the salt directly |
| `model_used` | `str` | Label for the dashboard (e.g. `"gpt-4o"`, `"stripe.charge"`) |
| `prompt_tokens` | `int` | Input tokens (0 if not an LLM call) |
| `completion_tokens` | `int` | Output tokens (0 if not an LLM call) |
| `event_kind` | `str` | Event type (e.g. `"llm.chat"`, `"custom.request"`) |
| `background` | `bool` | `True` = fire-and-forget (daemon thread). `False` = blocking |
| `host_url` | `str` | Override `RANBVAL_HOST` for this call |

**Environment variables:**

| Variable | Purpose |
|----------|---------|
| `RANBVAL_HOST` | Password-manager base URL (default: `https://api.ranbval.com`) |
| `RANBVAL_TELEMETRY` | `0` / `false` / `off` — disable all telemetry POSTs |
| `RANBVAL_TELEMETRY_DEBUG` | `1` / `true` — print telemetry failures to stderr |

> If no `client_salt` can be resolved, this is a **no-op** (silent). Safe to call even with plain (non-ranbval) keys.

---

### `secure_client()` / `build_secure_client()`

Wrap a third-party SDK class so it auto-decrypts and auto-logs telemetry on every call.

```python
from ranbval_sdk import load_ranbval, secure_client
import openai

load_ranbval()

# Returns an openai.OpenAI instance with auto-decrypt + telemetry
client = secure_client(
    openai.OpenAI,
    env_var="OPENAI_API_KEY",               # env var with the ranbval.* token
    key_kwarg="api_key",                    # constructor kwarg for the key
    method_path_to_patch="chat.completions.create",  # method to wrap for telemetry
)

# Use exactly like openai.OpenAI — telemetry fires automatically
response = client.chat.completions.create(model="gpt-4o", messages=[...])
```

**`build_secure_client()`** returns a **subclass** instead of an instance — use when you need to instantiate multiple times:

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

## 🔒 Security Architecture

```
Your Code
    │
    ├── load_ranbval()         Reads .ranbval* files → os.environ (no network, no decrypt)
    │
    ├── safe_decrypt(token, secret)
    │       │
    │       ├── 1. Repo allowlist check  →  GET /api/public/repo-policy?client_salt=...
    │       ├── 2. Billing/plan check   →  GET /api/public/billing-status?client_salt=...
    │       └── 3. AES-256-GCM decrypt  →  SecretString (value sealed, never printable)
    │
    ├── secret.use()           Only access point — pass directly to SDK/headers
    │
    └── emit_telemetry()       POST /api/telemetry → Ranbval Live Monitor
```

**Token format:** `ranbval.<client_salt>.<aes-gcm-blob>.<label>`
- `client_salt` — 10-char noise, used for session lookup and telemetry attribution
- `aes-gcm-blob` — IV + ciphertext, base64url encoded
- `label` — human-readable tag (`ahsan`, `openai`, etc.)

---

## 🌍 Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `RANBVAL_HOST` | `https://api.ranbval.com` | Password-manager base URL (no `/api` suffix) |
| `RANBVAL_ENV` | `development` | Active mode for layered config |
| `RANBVAL_VAULT_SECRET` | *(required)* | Vault password for `safe_decrypt()` |
| `RANBVAL_SKIP_REPO_CHECK` | `0` | `1` = skip Git remote allowlist check |
| `RANBVAL_SKIP_BILLING_CHECK` | `0` | `1` = skip subscription/plan check |
| `RANBVAL_TELEMETRY` | `on` | `0` / `false` = disable telemetry POSTs |
| `RANBVAL_TELEMETRY_DEBUG` | `0` | `1` = print telemetry errors to stderr |

---

## 🧪 Test with curl

**Check session exists:**
```bash
curl "https://api.ranbval.com/api/public/repo-policy?client_salt=YOUR_SALT"
```

**Check billing/plan:**
```bash
curl "https://api.ranbval.com/api/public/billing-status?client_salt=YOUR_SALT"
```

**Send a telemetry event:**
```bash
curl -X POST "https://api.ranbval.com/api/telemetry" \
  -H "Content-Type: application/json" \
  -d '{
    "client_salt": "YOUR_SALT",
    "machine_name": "curl-test",
    "repo_path": "/my/project",
    "model_used": "curl.test",
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "security": { "event_kind": "custom.request", "transport": "https" }
  }'
```

**Test decryption (Python):**
```bash
RANBVAL_SKIP_REPO_CHECK=1 \
RANBVAL_SKIP_BILLING_CHECK=1 \
RANBVAL_VAULT_SECRET="your_vault_secret" \
python -c "
import os
from ranbval_sdk import safe_decrypt
secret = safe_decrypt(os.environ['RANBVAL_TOKEN'], os.environ['RANBVAL_VAULT_SECRET'])
print(f'OK — {len(secret)} chars, value hidden: {secret}')
"
```

---

## 🔁 n8n — HTTP Request + Telemetry

No Python needed. Chain two **HTTP Request** nodes:

**Node 1 — Your API call** (OpenAI, Stripe, etc.) via HTTPS.

**Node 2 — Telemetry log** to Ranbval:

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

**Extract `client_salt` from a `ranbval.*` token in a Code node:**
```javascript
const token = $json.apiKey;
const salt = token.startsWith("ranbval.") ? token.split(".")[1] : null;
return [{ json: { client_salt: salt } }];
```

---

## 📋 Plans

| Plan | Price | Requests/mo | Secrets |
|------|-------|-------------|---------|
| **Starter** | $15/mo | 10,000 | 10 |
| **Growth** ⭐ | $49/mo | 100,000 | 50 |
| **Pro** | $129/mo | 500,000 | Unlimited |
| **Enterprise** | $499+/mo | Unlimited | Unlimited |

**Free trial:** 1 day · 1 project · 5 secrets · Full Growth features

→ **[Subscribe at ranbval.com](https://www.ranbval.com)**

---

## 📁 File Layout Example

```
my-project/
├── .ranbval                  ← shared defaults (commit this)
├── .ranbval.production       ← production overrides (commit this)
├── .ranbval.local            ← machine secrets (gitignore this!)
├── .ranbval.production.local ← prod + local (gitignore this!)
└── src/
    └── main.py
```

`.gitignore`:
```
.ranbval.local
.ranbval.*.local
```

---

## 🤝 Investors & Partnerships

Ranbval is looking for **CEOs and investors** who want to back the next generation of API secret governance.

If you are interested in backing an idea that solves a real pain for every engineering team using LLMs and third-party APIs — reach out through **[ranbval.com](https://www.ranbval.com)**.

---

*PyPI: [`ranbval-sdk`](https://pypi.org/project/ranbval-sdk/) · Docs: [api.ranbval.com/docs](https://api.ranbval.com/docs) · Dashboard: [ranbval.com](https://www.ranbval.com)*
