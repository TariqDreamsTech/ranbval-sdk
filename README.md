# Ranbval Python SDK

Decrypt Ranbval vault tokens in memory, optional telemetry to your password-manager, repo allowlist checks, and layered **`.ranbval*`** config.

**This package does not depend on OpenAI, Stripe, Anthropic, Mistral, or Supabase.** You `pip install` whichever vendor you use, then pass that SDK’s class to **`secure_client`** or **`build_secure_client`**.

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

## Quick start — any SDK (OpenAI, Stripe, …)

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

When you pass **`method_path_to_patch`**, the wrapper posts **platform-style** metadata to `POST {RANBVAL_HOST}/api/telemetry` on a **background thread** after that method returns (no token usage parsing — that stays generic).

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
