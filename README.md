# Ranbval Python SDK

A secure, fully Zero-Memory execution wrapper for AI and generic API clients. 
Instead of storing plaintext credentials in `os.environ`, this SDK keeps them completely invisible. It intercepts the client construction, performs a blind PBKDF2 decryption in-memory at runtime, securely passes the decrypted credential only to the relevant library, and immediately purges it.

## Quick Start (Pre-Built Clients)

For the most popular SDKs, we offer drop-in replacements. Simply swap your import and let Ranbval handle the encryption boundary without changing your codebase format.

### OpenAI
```python
import os
from ranbval_sdk import SecureOpenAI

os.environ["OPENAI_API_KEY"] = "ranbval.xxxxxxxxxx.[BLOB].ahsan"
os.environ["RANBVAL_VAULT_SECRET"] = "your_master_password"

client = SecureOpenAI()
# Uses native standard client methods safely behind the scenes
client.chat.completions.create(model="gpt-4", ...) 
```

### Anthropic / Mistral / Supabase
We offer similarly secure blind wrappers for other leading SDKs:
```python
from ranbval_sdk import SecureAnthropic, SecureMistral, SecureSupabase

anthropic_client = SecureAnthropic()
mistral_client = SecureMistral()
```

## Universal Custom Platform Wrapper

If you need to strictly encrypt secrets for an SDK that we don't natively ship (e.g. `Stripe`, `Twilio`, or internal APIs), you can use the Universal Integration Engine to wrap ANY Python class dynamically:

```python
from ranbval_sdk import build_secure_client
import stripe

# Generates a Drop-in Secure Proxy for the Stripe SDK dynamically
SecureStripe = build_secure_client(
    SDKClass=stripe.StripeClient,
    env_var_name="STRIPE_SECRET_KEY",
    key_kwarg="api_key"
)

# Completely encrypted in ENV. Handled securely in-memory.
stripe_client = SecureStripe()
```

## Telemetry

Pre-built clients enqueue **usage and security metadata** to your Ranbval API (`POST {RANBVAL_HOST}/api/telemetry`) on a **background worker thread** so model calls are not blocked.

| Variable | Meaning |
|----------|---------|
| `RANBVAL_HOST` | API base URL (default in SDK may differ by version; set explicitly in production) |
| `RANBVAL_TELEMETRY` | `0`, `false`, `off` — disable telemetry entirely |

For the full ingest schema, pagination, and dashboard behavior, see the **[ranbval-password-manager README](../ranbval-password-manager/README.md)** (Telemetry section).

## Git remote allowlist

If the project owner adds allowed repo URLs in the dashboard (or via `POST /api/projects/{id}/whitelist`), the SDK calls **`GET /api/public/repo-policy?client_salt=…`** and compares the result to the local **`git remote get-url origin`**. When **`enforce_allowlist`** is true (non-empty list), decrypt fails with a clear **`PermissionError`** before any provider API call.

| Variable | Meaning |
|----------|---------|
| `RANBVAL_HOST` | Must point at the password-manager API (path `/api/public/repo-policy` is appended internally). |
| `RANBVAL_SKIP_REPO_CHECK` | Set to `1` / `true` to skip the check (development only; not for production). |

Empty allowlist on the server means **no** client-side enforcement.
