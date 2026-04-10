# Ranbval Python runtime

This package **loads layered `.ranbval*` config** into `os.environ`, **decrypts `ranbval.*` vault tokens** when your code calls `safe_decrypt`, and **optionally sends telemetry** to your Ranbval password-manager (Live Monitor). It does **not** bundle other vendors’ SDKs or HTTP stacks—only `cryptography` and `certifi`.

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
