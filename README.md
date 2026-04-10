# Ranbval Python SDK

Load layered **`.ranbval*`** into the environment, decrypt **`ranbval.*`** tokens when **you** call **`safe_decrypt`**, and optionally **`emit_telemetry`** so your password-manager sees usage — with **any** HTTP client or vendor SDK you already use.

**No vendor SDKs are bundled.** OpenAI / Stripe / custom `requests` flows are all the same story: load env → call your API → ping telemetry if you want the Live Monitor.

## Install

```bash
pip install ranbval-sdk
```

Then in your project (examples):

```bash
pip install openai
# or: pip install anthropic stripe …
```

## Config: layered `.ranbval*`

Call **`load_ranbval()`** yourself (not on import).

```python
from ranbval_sdk import load_ranbval

load_ranbval()
```

Merge order (later overrides earlier): `.ranbval` → `.ranbval.{mode}` → `.ranbval.local` → `.ranbval.{mode}.local`. Mode from `load_ranbval(mode="production")` or `RANBVAL_ENV` / `ENVIRONMENT` / `ENV` (default `development`).

See [`.ranbval.example`](.ranbval.example). Add `.ranbval.local` to **`.gitignore`**.

## Quick start — env load + your own client + telemetry

`.ranbval` keeps **`ranbval.*`** tokens as-is in the environment (not decrypted at load time). You decrypt right before the call, then tell Ranbval a request happened:

```python
import os
import openai
from ranbval_sdk import load_ranbval, safe_decrypt, emit_telemetry

load_ranbval()
raw = os.environ["OPENAI_API_KEY"]
secret = os.environ["RANBVAL_VAULT_SECRET"]
api_key = safe_decrypt(raw, secret) if raw.startswith("ranbval.") else raw

client = openai.OpenAI(api_key=api_key)
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "hi"}],
)
emit_telemetry(
    vault_token_env="OPENAI_API_KEY",
    model_used="openai.chat.completions",
    prompt_tokens=resp.usage.prompt_tokens,
    completion_tokens=resp.usage.completion_tokens,
    background=True,
)
```

Same idea with **`requests`**, **`httpx`**, or an internal microservice: decrypt (if needed) → call → **`emit_telemetry(...)`** with a label in **`model_used`**. If the env var is not a **`ranbval.*`** token, pass **`client_salt="..."`** explicitly instead of **`vault_token_env`**.

## Optional — auto-wrap any SDK class

If you prefer Ranbval to inject the key and optionally patch one method for background telemetry:

```python
import openai
from ranbval_sdk import load_ranbval, secure_client

load_ranbval()
client = secure_client(
    openai.OpenAI,
    env_var="OPENAI_API_KEY",
    key_kwarg="api_key",
    method_path_to_patch="chat.completions.create",  # optional: telemetry after each call
)
client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "hi"}],
)
```

```python
import anthropic
from ranbval_sdk import load_ranbval, secure_client

load_ranbval()
claude = secure_client(
    anthropic.Anthropic,
    env_var="ANTHROPIC_API_KEY",
    key_kwarg="api_key",
    method_path_to_patch="messages.create",
)
```

```python
import stripe
from ranbval_sdk import load_ranbval, secure_client

load_ranbval()
stripe_client = secure_client(
    stripe.StripeClient,
    env_var="STRIPE_SECRET_KEY",
    key_kwarg="api_key",
)
```

Lower-level: **`build_secure_client(SDKClass, env_var_name, key_kwarg, method_path_to_patch=None)`** returns a **class** you can reuse or subclass.

## Low-level decrypt

```python
from ranbval_sdk import safe_decrypt

plain = safe_decrypt("ranbval.noise.blob.ahsan", os.environ["RANBVAL_VAULT_SECRET"])
```

## Telemetry

**`emit_telemetry`** and **`secure_client(..., method_path_to_patch=...)`** both POST to `POST {RANBVAL_HOST}/api/telemetry`. Use **`emit_telemetry`** when you own the HTTP/SDK call; use **`method_path_to_patch`** when you want a background ping after one wrapped method returns (generic counts unless you pass token fields yourself via **`emit_telemetry`**).

| Variable | Meaning |
|----------|---------|
| `RANBVAL_HOST` | Password-manager origin (no `/api`). Defaults to hosted service. |
| `RANBVAL_TELEMETRY` | `0` / `false` / `off` — disable |
| `RANBVAL_TELEMETRY_DEBUG` | `1` / `true` — print POST failures to stderr |

**Auth service URL is not** `RANBVAL_HOST` — telemetry goes to the password-manager API only.

**SSL on macOS:** `certifi` is used for HTTPS; `pip install -U certifi` if verify fails.

## Git remote allowlist

| Variable | Meaning |
|----------|---------|
| `RANBVAL_HOST` | Same origin as telemetry (`/api/public/repo-policy`). |
| `RANBVAL_SKIP_REPO_CHECK` | `1` / `true` — skip (dev only). |

See **[ranbval-password-manager README](../ranbval-password-manager/README.md)** for ingest schema and dashboard behavior.
