# Ranbval Python runtime

This package merges **layered `.ranbval*` files** into `os.environ`, keeps **`ranbval.*` vault tokens opaque** until **`safe_decrypt`** runs, and can **optionally POST usage** to your Ranbval password manager (Live Monitor). It ships only **`cryptography`** and **`certifi`**—your app keeps its own HTTP client and vendor SDKs.

---

## Why we built Ranbval

With so many LLM models and APIs available today, **managing secrets has become a nightmare**. Someone shares an API key, it gets forwarded, and suddenly **usage shows up on a bill nobody planned for**. It is hard to know **which API** is in use, **in which repository**, or **on which device**—and who actually burned the tokens.

**That is why we built Ranbval.** It is a **security and monitoring layer** for API keys and secrets, not just another place to paste strings. Here is how it changes the game:

- **Total control** — You decide **which Git repositories** may use a credential. If a repo is not authorized, the secret **cannot be used** for real API calls—even if a token or key string leaked.
- **Encrypted secrets** — **No plaintext `.env` in source control.** Prefer `load_ranbval()` over scattering `load_dotenv()` everywhere: `.ranbval*` files hold config, and values shaped like `ranbval.<salt>.<ciphertext>.<label>` stay encrypted until your code explicitly decrypts them.
- **Full monitoring** — **Telemetry and dashboards** tie usage back to credentials and context so you can see what happened—including failed or suspicious paths—instead of flying blind.

**No more paying for other people’s usage. Your secrets, your rules.**

The Python runtime is on PyPI as [`ranbval-sdk`](https://pypi.org/project/ranbval-sdk/). **Any HTTPS client** (including **n8n’s HTTP Request** node) can POST to the same telemetry API—see [n8n](#n8n-http-request--telemetry-over-https) below. Deeper no-code / REST tooling is still expanding.

We are talking to **CEOs and investors** who want to back the next wave of API secret governance; if that is you and you want to connect, reach out through the channels listed on the main Ranbval / password-manager project.

---

## How it works (end-to-end)

1. **Config on disk** — You keep `KEY=value` lines in `.ranbval` and related files (see below). Values can be plain text or **`ranbval.<salt>.<ciphertext>.<label>`** tokens produced by the vault.
2. **`load_ranbval()`** — Merges those files into **`os.environ`**. Encrypted tokens are stored **as-is**; nothing is decrypted during this step.
3. **Your code** — You read `os.environ`, call **`safe_decrypt(...)`** when a value is a `ranbval.*` token and you need the real secret for an API call.
4. **`emit_telemetry(...)`** (optional) — After an outbound call, you POST a small payload to the password-manager so usage is attributed to the right vault credential (via **client salt** inside the token, or an explicit salt).

Importing the package **does not** load files or touch the network. You choose **where** to call `load_ranbval()` (e.g. start of `main`, app factory, worker entrypoint).

---

## Install

```bash
pip install ranbval-sdk
```

Runtime dependencies are **cryptography** and **certifi** (for HTTPS verification). Everything else is your app’s own stack.

---

## `load_ranbval()` — layered config

Call it **explicitly** when your process should pick up `.ranbval*` settings:

```python
from ranbval_sdk import load_ranbval

load_ranbval()
```

### Where files are found

With **no arguments**, the SDK walks **from the current working directory upward** until it finds a directory that contains **`.ranbval`** or any **`.ranbval.*`** file. That directory is the **config root**.

Helpers (optional):

- **`find_ranbval_directory(start=None)`** — config root path or `None`
- **`find_ranbval_file(start=None)`** — path to base `.ranbval` or first layer file
- **`resolve_ranbval_mode(mode=None)`** — which mode name is active (see below)

### Which mode is used

Mode selects **`.ranbval.{mode}`** and **`.ranbval.{mode}.local`** in the merge. Resolution order:

1. `load_ranbval(mode="...")` if you pass `mode`
2. Else `RANBVAL_ENV`, then `ENVIRONMENT`, then `ENV`
3. Default **`development`**

### Merge order (later wins)

For the chosen mode, existing files are merged in this order:

1. `.ranbval`
2. `.ranbval.{mode}`
3. `.ranbval.local`
4. `.ranbval.{mode}.local`

Duplicate keys: **later file overrides earlier**.

### Applying values to `os.environ`

For each merged `KEY=value`:

- **`override=False`** (default): set only if the key is missing or currently **empty** in `os.environ`.
- **`override=True`**: merged values **always** replace what was already in `os.environ`.

**Return value:** `True` if at least one file was read, else `False`.

### Single file instead of layers

```python
load_ranbval("/absolute/or/relative/path/to/file")
```

Only that file is parsed; layer discovery is skipped.

### Optional `start` directory

```python
load_ranbval(start="/path/to/project/root")
```

Search for the config root begins at `start` instead of `os.getcwd()`.

---

## Vault tokens vs plain env values

- **Plain** values in `.ranbval*` are copied into the environment unchanged.
- **`ranbval.*`** tokens stay **opaque strings** in the environment until you call **`safe_decrypt(encoded, RANBVAL_VAULT_SECRET)`** (or your app’s equivalent secret).

Token shape: `ranbval.<client_salt>.<blob>.<label>` — telemetry uses **`<client_salt>`** when you pass `vault_token_env="..."` pointing at that env var.

---

## `safe_decrypt`

```python
from ranbval_sdk import safe_decrypt
import os

load_ranbval()
raw = os.environ["MY_API_CREDENTIAL"]
secret = os.environ["RANBVAL_VAULT_SECRET"]
plain = safe_decrypt(raw, secret) if raw.startswith("ranbval.") else raw
# use `plain` in headers, clients, etc.
```

Use this only when you actually need the secret; avoid logging it.

---

## `emit_telemetry`

Sends one row to **`{RANBVAL_HOST}/api/telemetry`** (password-manager origin only—**no** `/api` suffix in `RANBVAL_HOST`).

Typical pattern after **your** HTTP or SDK call:

```python
from ranbval_sdk import load_ranbval, emit_telemetry

load_ranbval()
# ... your request using decrypted credential if needed ...

emit_telemetry(
    vault_token_env="MY_API_CREDENTIAL",  # env var holding a ranbval.* token → salt extracted
    model_used="my-service.endpoint",     # free-form label in the dashboard
    prompt_tokens=0,
    completion_tokens=0,
    background=True,
)
```

If the credential is **not** a `ranbval.*` string, pass **`client_salt="..."`** instead of `vault_token_env`, or the call is a **no-op** (no salt → no POST).

| Variable | Purpose |
|----------|---------|
| `RANBVAL_HOST` | Password-manager base URL (default: hosted instance). |
| `RANBVAL_TELEMETRY` | `0` / `false` / `off` / `no` — skip telemetry POSTs. |
| `RANBVAL_TELEMETRY_DEBUG` | `1` / `true` — print telemetry failures to stderr. |

HTTPS uses **`certifi`**; upgrade `certifi` if certificate verification fails on your machine.

---

## Test with `curl`: server lookup, telemetry (logs), and decryption

**What you need from the vault**

- A session whose stored credential looks like `ranbval.<salt>.<blob>.<label>` (copy the full string for decryption; for HTTP calls you only need **`<salt>`** — the segment between the first and second `.`).
- **`RANBVAL_VAULT_SECRET`** — same secret you use with the Python SDK to decrypt (not sent in these `curl` commands).

Set a base URL (**no** trailing slash, **no** extra `/api` on the variable):

```bash
export RANBVAL_HOST="https://ranbval-password-manager.onrender.com"   # or your self-hosted origin
export YOUR_SALT="paste_salt_here"   # e.g. if token is ranbval.abcdef1234.xxx.yyy → abcdef1234
```

### 1) `curl` — confirm the password manager knows this token (session exists)

Resolves the same way telemetry does (lookup by `ranbval.{salt}.%` in the database):

```bash
curl -sS "${RANBVAL_HOST}/api/public/repo-policy?client_salt=${YOUR_SALT}"
```

- **200** — JSON with `allowed_repos` and `enforce_allowlist` (allowlist rules for decrypt/telemetry).
- **404** — `Unknown Ranbval session for this client salt` → wrong salt or no matching session.

### 2) `curl` — send telemetry (HTTPS log line to Live Monitor)

**POST** JSON to `/api/telemetry`. Minimal body only needs `client_salt`, `machine_name`, and `repo_path`:

```bash
curl -sS -X POST "${RANBVAL_HOST}/api/telemetry" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_salt\": \"${YOUR_SALT}\",
    \"machine_name\": \"curl-test\",
    \"repo_path\": \"$(pwd)\",
    \"model_used\": \"curl.manual-test\",
    \"prompt_tokens\": 0,
    \"completion_tokens\": 0,
    \"git_url\": \"$(git config --get remote.origin.url 2>/dev/null || echo '')\",
    \"security\": {
      \"event_kind\": \"custom.request\",
      \"transport\": \"https\",
      \"vault_token_format\": \"ranbval\",
      \"client_platform\": \"curl\",
      \"ci_environment\": false
    }
  }"
```

Expect JSON like `{"status":"ok","recorded_id":"…","is_authorized":true}`. If the project has an **allowed-repo list** and `git_url` does not match, `is_authorized` may be `false` but the attempt can still be stored / alerted—see the password-manager README.

### 3) Prove **decryption** (not `curl` — local Python only)

There is **no** public HTTP endpoint that returns your plaintext API key. Decryption runs in your process via **`safe_decrypt(token, RANBVAL_VAULT_SECRET)`** (after optional repo check against `RANBVAL_HOST`).

```bash
export RANBVAL_TOKEN='ranbval....'           # full token from the vault; avoid committing this
export RANBVAL_VAULT_SECRET='...'          # your vault secret
# export RANBVAL_SKIP_REPO_CHECK=1         # optional while testing outside an allowlisted git clone

python -c "import os; from ranbval_sdk import safe_decrypt; p=safe_decrypt(os.environ['RANBVAL_TOKEN'], os.environ['RANBVAL_VAULT_SECRET']); print('decrypt_ok', len(p), 'chars')"
```

If this prints `decrypt_ok … chars`, the **encryption envelope** for that token matches your secret. Then **`curl` telemetry** (step 2) exercises the **HTTPS logging path** end-to-end.

---

## n8n: HTTP Request + telemetry over HTTPS

The Live Monitor ingest URL is the same for Python and for **n8n**: **`POST https://<RANBVAL_HOST>/api/telemetry`** (no `/api` suffix in the host variable—only on the path). Your **vendor call** (OpenAI, Stripe, etc.) should use **HTTPS**; the **telemetry** call should also use **HTTPS** on your password-manager host. Both are ordinary TLS requests from n8n’s **HTTP Request** node.

**Typical workflow**

1. **HTTP Request** — Call the external API (HTTPS), using n8n credentials for the real API key.
2. **HTTP Request** — `POST` JSON to `https://<RANBVAL_HOST>/api/telemetry` so usage is logged the same way as `emit_telemetry`.

Chain **2** after **1** so telemetry runs when the request finishes (or only on success, using n8n’s error branch / IF node if you want). n8n does not support a single node that “wraps” arbitrary URLs with hooks; two nodes (or a small **Code** node that calls both via `$helpers.httpRequest`) is the intended pattern.

**`client_salt` in n8n**

The server attributes the row to your vault session using **`client_salt`** (the segment after `ranbval.` in a token `ranbval.<salt>.<ciphertext>.<label>`). If you still have that full token string in a credential or expression, extract salt with a **Code** node, for example:

```javascript
const key = $json.apiKey; // or pull from credentials / previous node
if (typeof key !== "string" || !key.startsWith("ranbval.")) {
  return [{ json: { client_salt: null } }];
}
return [{ json: { client_salt: key.split(".")[1] } }];
```

If n8n only stores a **plain** API key (no `ranbval.*` string), copy the **salt** from the Ranbval session / dashboard and keep it in a **static workflow value** or credential field used only for telemetry (not the secret itself).

**Example JSON body** (HTTP Request → Body Content Type **JSON**; adjust with n8n expressions):

```json
{
  "client_salt": "{{ $json.client_salt }}",
  "machine_name": "n8n",
  "repo_path": "{{ $workflow.name }}",
  "git_url": "https://github.com/your-org/your-repo.git",
  "model_used": "openai.chat",
  "prompt_tokens": 0,
  "completion_tokens": 0,
  "security": {
    "event_kind": "custom.request",
    "transport": "https",
    "vault_token_format": "ranbval",
    "client_platform": "n8n",
    "ci_environment": false
  }
}
```

Fill **`git_url`** with the repo URL your Ranbval project allowlist expects (if you use allowlists). Token counts can be filled from the previous node’s response if the API returns them.

Full field list: **[ranbval-password-manager README — Telemetry ingest](../ranbval-password-manager/README.md#ingest--post-apitelemetry)**.

---

## Optional: `secure_client` / `build_secure_client`

If you use a **class-based** third-party client that takes an API key in the constructor, you can wrap that class so it:

- reads a named env var,
- decrypts if it looks like `ranbval.*`,
- passes the plain key into the constructor under the keyword your client expects,
- optionally wraps **one** dotted method path to call **`emit_telemetry`** on the way back.

```python
from ranbval_sdk import load_ranbval, secure_client
import some_sdk  # your dependency, not from this package

load_ranbval()
client = secure_client(
    some_sdk.Client,
    env_var="MY_API_CREDENTIAL",
    key_kwarg="api_key",
    method_path_to_patch="resources.create",  # optional
)
```

**`build_secure_client(...)`** returns a **subclass** instead of an instance—same parameters at the class level.

---

## Git remote allowlist (optional)

The dashboard **Allowed Git remotes** list stores **remote URLs** (e.g. `https://github.com/org/repo.git`), **not** a folder path on disk. Enforcement runs inside **`safe_decrypt()`**: before decrypting a `ranbval.*` token, the SDK calls `GET {RANBVAL_HOST}/api/public/repo-policy?client_salt=…`. If the project has a **non-empty** allowlist, decryption raises **`PermissionError`** unless `git config --get remote.origin.url` (resolved from your **current working directory** upward to the repo root) normalizes to one of those URLs.

So: running the same script from `…/ranbval-external-test/venv` or from `…/ranbval-sdk` **both succeed** if they sit under **one Git clone** whose `origin` is allowlisted. To block usage from another clone, that other clone must have a **different** `origin` (or no origin)—the filesystem path alone is never compared.

| Variable | Purpose |
|----------|---------|
| `RANBVAL_HOST` | Must reach the password-manager so repo policy can be loaded. |
| `RANBVAL_SKIP_REPO_CHECK` | `1` / `true` — skip policy fetch and origin check (**local dev only**). |

---

## Example layout

See [`.ranbval.example`](.ranbval.example). Put machine-only secrets in **`.ranbval.local`** / **`.ranbval.{mode}.local`** and add those files to **`.gitignore`**.

---

## Further reading

In this monorepo, **[ranbval-password-manager README](../ranbval-password-manager/README.md)** describes ingest schema, dashboard behavior, and backend APIs.
