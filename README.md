# Ranbval Python SDK

A secure, fully Zero-Memory execution wrapper for AI and generic API clients. 
Instead of storing plaintext credentials in `os.environ`, this SDK keeps them completely invisible. It intercepts the client construction, performs a blind PBKDF2 decryption in-memory at runtime, securely passes the decrypted credential only to the relevant library, and immediately purges it.

## Config: layered `.ranbval*` (like `.env` / `.env.local`)

**You import and call `load_ranbval()` yourself** (no automatic load on `import ranbval_sdk`).

```python
from ranbval_sdk import load_ranbval, SecureOpenAI

load_ranbval()  # merges files, see below
client = SecureOpenAI()
```

From the **current working directory upward**, the SDK finds the first directory that contains `.ranbval` or any `.ranbval.*` file, then **merges** these files **in order** (later overrides earlier for the same key):

| Order | File | Purpose |
|------:|------|---------|
| 1 | `.ranbval` | Shared defaults |
| 2 | `.ranbval.development` or `.ranbval.production` | Picked by **mode** (see below) |
| 3 | `.ranbval.local` | Machine-only overrides (gitignore) |
| 4 | `.ranbval.development.local` / `.ranbval.production.local` | Mode + local |

**Mode** (`development` vs `production`): `load_ranbval(mode="production")`, or set `RANBVAL_ENV` / `ENVIRONMENT` / `ENV` **before** calling `load_ranbval()`, or default is `development`.

- **Plaintext** variables stay readable in the file; **Ranbval tokens** stay encoded on disk; plaintext API keys exist only briefly in memory when used.
- **`RANBVAL_HOST`** optional — SDK defaults to the hosted password-manager if unset.
- **`override=True`**: merged file values always replace `os.environ`; default `False` keeps existing shell/CI env vars.

Single file only: `load_ranbval("/path/to/.ranbval")`.

Helpers: `find_ranbval_directory()`, `find_ranbval_file()`, `resolve_ranbval_mode()`.

See [`.ranbval.example`](.ranbval.example). Add `.ranbval.local` and `*.local` to **`.gitignore`**.

## Quick Start — one function, any built-in provider

Use **`secure_client("openai")`**, **`secure_client("anthropic")`**, etc. You do **not** need a different import/class per vendor—only the provider string (and optional `env_var` if your key is not under the default name).

```python
import os
from ranbval_sdk import load_ranbval, secure_client

load_ranbval()
gpt = secure_client("openai")
gpt.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}])

claude = secure_client("anthropic")
# mistral = secure_client("mistral")
# sb = secure_client("supabase", supabase_url=os.environ["SUPABASE_URL"])

# Custom env name for the same provider:
# secure_client("openai", env_var="MY_LLM_KEY")

# Any other SDK — same function, no separate build_secure_client in your app:
# import stripe
# secure_client(sdk_class=stripe.StripeClient, env_var="STRIPE_SECRET_KEY", key_kwarg="api_key")
```

**Custom secrets:** put `STRIPE_SECRET_KEY=ranbval....ahsan` (or plain) in `.ranbval*`, then only `secure_client(sdk_class=..., env_var="STRIPE_SECRET_KEY", key_kwarg="api_key")` — you never import `build_secure_client` yourself.

**Production:** same code; use `load_ranbval(mode="production")` or `RANBVAL_ENV=production` and layered `.ranbval.production` — nothing “special” breaks prod; unset vars still fall through to defaults (e.g. hosted `RANBVAL_HOST`).

## Pre-built classes (optional)

You can still import **`SecureOpenAI`**, **`SecureAnthropic`**, etc. if you prefer explicit types.

### OpenAI
```python
from ranbval_sdk import load_ranbval, SecureOpenAI

load_ranbval()
client = SecureOpenAI()
client.chat.completions.create(model="gpt-4", ...)
```

Or set variables manually (e.g. notebooks):

```python
import os
from ranbval_sdk import SecureOpenAI

os.environ["OPENAI_API_KEY"] = "ranbval.xxxxxxxxxx.[BLOB].ahsan"
os.environ["RANBVAL_VAULT_SECRET"] = "your_master_password"

client = SecureOpenAI()
```

### Anthropic / Mistral / Supabase
We offer similarly secure blind wrappers for other leading SDKs:
```python
from ranbval_sdk import load_ranbval, SecureAnthropic, SecureMistral, SecureSupabase

load_ranbval()
anthropic_client = SecureAnthropic()
mistral_client = SecureMistral()
```

## Universal Custom Platform Wrapper

Prefer **`secure_client(sdk_class=..., env_var=..., key_kwarg=...)`** so you do not define a one-off wrapper class per vendor:

```python
from ranbval_sdk import load_ranbval, secure_client
import stripe

load_ranbval()
stripe_client = secure_client(
    sdk_class=stripe.StripeClient,
    env_var="STRIPE_SECRET_KEY",
    key_kwarg="api_key",
    # method_path_to_patch="charges.create",  # optional telemetry hook
)
```

Lower-level: **`build_secure_client`** still exists if you want a reusable class alias (e.g. `SecureStripe = build_secure_client(...)`).

## Telemetry

Pre-built clients enqueue **usage and security metadata** to your Ranbval API (`POST {RANBVAL_HOST}/api/telemetry`) on a **background worker thread** so model calls are not blocked.

### Hosted production (dashboard online)

Use the **password-manager** origin (default in recent SDK versions: `https://ranbval-password-manager.onrender.com`). The **auth** URL is only for login in the browser; telemetry never goes there. Your Ranbval token must come from the **same** Supabase project as the dashboard, or the server will not attach events to your project.

| Variable | Meaning |
|----------|---------|
| `RANBVAL_HOST` | Password-manager origin (no `/api` suffix). Defaults to the hosted service; set to `http://localhost:8006` for local backends. |
| `RANBVAL_TELEMETRY` | `0`, `false`, `off` — disable telemetry entirely |
| `RANBVAL_TELEMETRY_DEBUG` | `1` / `true` — print failures from `POST …/api/telemetry` to stderr (wrong `RANBVAL_HOST`, network, etc.) |

**Important:** `RANBVAL_HOST` must be the **password-manager** origin (telemetry + repo policy). Do not point it at the auth service; that URL does not ingest telemetry.

**SSL errors on macOS** (`CERTIFICATE_VERIFY_FAILED`): the SDK depends on `certifi` for HTTPS to telemetry and repo-policy. Run `pip install -U certifi ranbval-sdk` or use the Python.org installer’s “Install Certificates” command if issues persist.

For the full ingest schema, pagination, and dashboard behavior, see the **[ranbval-password-manager README](../ranbval-password-manager/README.md)** (Telemetry section).

## Git remote allowlist

If the project owner adds allowed repo URLs in the dashboard (or via `POST /api/projects/{id}/whitelist`), the SDK calls **`GET /api/public/repo-policy?client_salt=…`** and compares the result to the local **`git remote get-url origin`**. When **`enforce_allowlist`** is true (non-empty list), decrypt fails with a clear **`PermissionError`** before any provider API call.

| Variable | Meaning |
|----------|---------|
| `RANBVAL_HOST` | Same origin as telemetry (paths like `/api/public/repo-policy` are appended internally). |
| `RANBVAL_SKIP_REPO_CHECK` | Set to `1` / `true` to skip the check (development only; not for production). |

Empty allowlist on the server means **no** client-side enforcement.
