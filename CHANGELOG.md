# Changelog

All notable changes to `ranbval-sdk` are documented here.

---

## [4.3.0] - 2026-08-05

### Security

- **`RANBVAL_HOST` can no longer redirect the control plane.** Every server-side control here — the
  repo allowlist above all — is only as trustworthy as the server being asked, and the host was
  read from the environment without constraint. Anyone who could set an environment variable could
  point the SDK at a server of their own, have it answer `{"enforce_allowlist": false}`, and walk
  straight past the allowlist. Demonstrated with a nine-line local HTTP server, not theorised:

  ```
  RANBVAL_HOST=http://127.0.0.1:8799  ->  decrypt succeeded, policy supplied by the attacker
  ```

  That is the control this documentation has been calling server-side and unbypassable. It was
  bypassable with one variable.

  The rule now:

  | | |
  |---|---|
  | No configuration | the official host — the common case needs nothing |
  | A host passed **in code** (`load_ranbval(host=...)`, `proxy_request(host_url=...)`) | honoured |
  | `RANBVAL_HOST` naming anything else | **refused** (`host_not_allowed`) |

  A self-hosted control plane opts in **from code**, once:

  ```python
  from ranbval_sdk import allow_host_override
  allow_host_override()
  ```

  Deliberately not an environment variable and not a `.ranbval` key — both are settable by anyone
  who can influence the process, and this is the switch that decides which server gets to say
  whether a decrypt is allowed. Code is a boundary an attacker holding only the environment cannot
  cross. That is the same reasoning applied to the guard opt-outs, and it should have been applied
  here first.

### Added

- **`allow_host_override()` / `is_host_override_allowed()`** — the code-level opt-in above.

---

## [4.2.0] - 2026-07-30

### Added

- **The output guard now installs itself at the first decrypt.** It was installed by
  `load_ranbval()` only, which left a real hole: `safe_decrypt(token, secret)` called directly —
  a script, a notebook cell, a REPL — produced a value with no guard at all, and
  `print(f"{value}")` emitted the credential in full. Measured, not assumed:

  ```
  before:  load_ranbval() skipped  ->  guard installed? False  ->  print leaked the key
  after:   load_ranbval() skipped  ->  guard installs on .use()  ->  PermissionError
  ```

  `SecretString.use()` now raises the guard before it produces any plaintext, so the value that
  triggered the install is itself registered — otherwise the very first secret, the one most
  likely to be printed while debugging, would be the one the guard could not recognise.

  An explicit refusal is remembered rather than inferred: `load_ranbval(guard_stdout=False)` and
  `uninstall_output_guards()` both record the opt-out, so the next decrypt does not put back what
  the caller just declined.

---

## [4.1.1] - 2026-07-30

### Removed

- **`RANBVAL_ALLOWED_PATHS` is gone.** It confined a config to a subtree, and it shipped in 4.1.0
  described as "scoping, not a security boundary". On review that framing was not enough: the
  setting lived in the `.ranbval` file itself, so any process able to edit your files — the AI
  coding agent it was most often reached for, a compromised dependency, a script — could edit the
  fence as easily as walk past it.

  A control whose only adversary can also delete it is not a weak control; it is a misleading one.
  It occupies the place in a reader's mind where a real control should be. Removing it is the same
  judgement applied to the `.encode()` guard in 3.7.0: a mechanism that reads as protection and
  provides none costs more than the gap it appeared to fill.

  > **⚠️ If you set this key, it is now ignored, silently.** `RANBVAL_*` names are exempt from
  > classification, so the line will not error — it simply stops doing anything. Search your
  > `.ranbval` files for it and delete it, so nobody later reads that line as an active control.

  **Use the repo allowlist instead.** It is checked against your `git remote origin` on every
  decrypt, and the policy is fetched from the control plane rather than read from a file on the
  machine — so the same agent cannot edit it out of the way. For a credential where even that is
  not enough, a `PROXY_` secret is never decrypted locally at all.

  Strictly, removing a shipped feature is a major change. It is released as a patch because 4.1.0
  was published hours earlier, and shipping a control that overstates itself for longer would be
  the larger harm.

---

## [4.1.0] - 2026-07-28

### Added

- **`RANBVAL_ALLOWED_PATHS` — confine a config to a subtree.** `.ranbval` is found by walking
  *upward* from the working directory, so a config placed high in a tree is picked up by every
  project beneath it, including ones that should never see those credentials. This key confines
  it:

  ```bash
  # .ranbval
  RANBVAL_ALLOWED_PATHS=.              # this directory and everything under it
  RANBVAL_ALLOWED_PATHS=./content      # one subtree
  RANBVAL_ALLOWED_PATHS=./api:./jobs   # two, nothing else
  ```

  **Subdirectories inherit.** The test is "is the working directory at or below an allowed
  directory", so a folder created later under an allowed path works with no config change.
  Relative entries resolve against the directory holding `.ranbval`, so the file stays portable
  across machines and checkouts; absolute paths are accepted too. An absent or empty value means
  no restriction — a typo must not brick a config.

  Path components are compared, not string prefixes, so a sibling such as `content-backup` does
  not match an allowed `content`.

  *Honest limit — this is scoping, not a security boundary.* Anyone holding the project secret can
  run from an allowed path or copy the files into one. It stops the wrong project picking up a
  parent's credentials by accident, which is the mistake that actually happens in a monorepo. It
  does not stop someone who wants the values; for that, the repo allowlist (server-side,
  unbypassable) or a `PROXY_` secret is the mechanism.

- **Pre-commit hooks, at both commit and push.** `.pre-commit-config.yaml` splits the work by
  cost, because a commit hook that takes ten seconds gets bypassed with `--no-verify` — the exact
  failure mode this project studies:

  | stage | hooks |
  |---|---|
  | `pre-commit` | ruff (lint + format), gitleaks, bandit, actionlint, codespell, `ranbval check`, blanket-`noqa`/blanket-`type: ignore` checks, `eval` and `log.warn` bans, whitespace/EOL/YAML/TOML/JSON, merge- and case-conflict, symlink checks, submodule ban, shebang/executable consistency, docstring-first, test-file naming, large-file guard, `detect-private-key` |
  | `pre-push` | mypy, the full test suite, `pip-audit` on the declared dependencies, the CHANGELOG-entry gate, and a real `build` + `twine check` |

  `pip-audit` runs against `[project].dependencies` rather than the ambient environment. Plain
  `pip-audit` reports every package in whatever virtualenv is active — an editor plugin, another
  project's leftovers — none of which ship with this SDK, and a hook that reports things the
  author cannot fix is a hook that gets skipped.

  **`black` is deliberately absent.** `ruff-format` is black's formatting model reimplemented;
  running both makes them disagree on edge cases and rewrite each other's output every commit.

  Hook revisions and the tools CI installs both track latest rather than pinned versions. The
  first CI run of these hooks failed because the local hooks use `language: system` — they run
  whatever the developer has installed — while CI installed a newer `mypy`, so the suite was green
  locally and red in CI. Keep your own tools current (`pip install -U pytest mypy pip-audit build
  twine pre-commit`) or the split returns.

  **CI runs every hook again, at both stages.** `.git/hooks` is never committed, so a fresh clone
  has none until someone runs the install, and `--no-verify` skips them even when present. The CI
  job is the copy that cannot be bypassed; the local hooks exist to give the same answer in
  seconds instead of after a push and a queue.

  Install both stages (the second is *not* installed by `pre-commit install` alone):

  ```bash
  pre-commit install --hook-type pre-commit --hook-type pre-push
  ```

  The build hook builds into a temporary directory rather than `./dist`, deliberately: a stale
  wheel left in `dist/` is a live hazard, since `twine upload dist/*` publishes every version
  sitting there and a published version can never be replaced.

- **`httpx` is now a declared optional dependency** (`pip install ranbval-sdk[httpx]`).
  `integrations.httpx_transport` imports it at module level, but nothing declared it, so type
  checking could not resolve it and a user had no way to know what that integration required.

### Fixed

- **The transport would open any URL scheme.** `urlopen` honours `file:`, `ftp:` and registered
  custom schemes, and the host comes from configuration (`RANBVAL_HOST`, `host_url=`) — so a host
  pointed at `file:///etc/passwd` made the SDK read it. The scheme is now restricted to `http`
  and `https`, with anything else raising `RanbvalConfigError` (`disallowed_url_scheme`). Found by
  bandit (B310) while wiring the hooks, and fixed rather than suppressed.

- **`cli/check.py` reused a name bound by an earlier `except ... as e`**, which Python deletes at
  block exit. Not a runtime fault, but exactly the shadowing that becomes one under edit.

- **`scripts/audit_deps.py` reported a missing tool as a vulnerability finding.** When `pip-audit`
  was not installed it printed *"vulnerable dependencies among: …"* — a red result naming packages
  that were never audited. "The tool is absent" and "the dependencies are vulnerable" are different
  facts, and a security tool that conflates them is the failure this project is about. It now says
  which one it is.

### Changed

- **The codebase now passes ruff, ruff-format, mypy and bandit cleanly.** All four were configured
  in `pyproject.toml` but never enforced anywhere; enabling them surfaced 12 lint errors, 21
  unformatted files and 15 type errors, all now resolved. Notifier and gate slots that were typed
  `object` and then called are typed as the callables they are; `__reduce_ex__` overrides match
  the signature they override.

---

## [4.0.1] - 2026-07-28

### Fixed

Three paths could still put a live credential on a terminal or in a log after 4.0.0. Found by
measuring against the guard rather than assuming it was complete:

```
print(f"{v:.8}")           leaked a prefix
sys.stderr.write(f"{v}")   leaked in full
logging.info(f"{v}")       leaked in full
```

- **stderr is now guarded alongside stdout.** That is where `logging`'s default handler writes,
  and a credential in a log line outlives the terminal it was printed to. `logging` swallows
  handler exceptions, so such a call prints `--- Logging error ---` rather than propagating a
  failure — but the credential does not reach the stream, which is the point.

- **A truncating format spec now raises.** `f"{key:.8}"` yields a *prefix*, and a prefix is not
  the value, so no content check at the destination can recognise it — it would print straight
  past the guard. This one has to be caught at the source, and is: a precision spec on a secret
  raises `RanbvalSecurityError`. Padding is unaffected, including a `.` used as a fill character
  (`f"{key:.<40}"`), which truncates nothing — the spec is parsed for a real precision rather
  than searched for a dot.

Passing a secret to a client library is untouched: `f"Bearer {key}"` and
`OpenAI(api_key=use.OPENAI_KEY)` still work. The line is between handing a value to a library and
writing it where a human or a log aggregator reads it.

### Documented

- **The guard covers the streams as they were at install time.** A stream replaced afterwards —
  a redirect, a test capture fixture, a handler opened on a new file object — is a different
  object and is not patched. There is now a test asserting exactly that, so the limit cannot
  quietly turn into a false promise.

---

## [4.0.0] - 2026-07-28

### Breaking

- **The stdout guard is now on by default.** `load_ranbval()` installs it during load. Code that
  printed a formatted secret — `print(f"{key.use()}")`, `print("Bearer " + key.use())` — used to
  emit the plaintext and now raises `PermissionError`. That is the point: it was a live credential
  going to a terminal, a CI log, or a container's stdout.

  Opt out with `load_ranbval(guard_stdout=False)`, or `uninstall_output_guards()` at runtime, if
  patching `builtins.print` is unacceptable in your process or you cannot accept that the guard
  retains each revealed plaintext for the life of the process. The opt-out is deliberately **not**
  an environment variable — an attacker able to set the environment should not be able to switch a
  security control off for free.

  Installed at load time rather than left to the caller because only that ordering is guaranteed to
  precede the first decrypt. A guard installed after a reveal cannot recognise that value once it
  has been formatted into an ordinary string, giving partial coverage that reads as full coverage;
  `install_output_guards()` now warns when it is called late, naming how many reveals it missed.

### Added

- **File-mode guard on the root-key file.** The project secret is the one value that cannot be
  encrypted, so the only thing between another account on the machine and the whole vault is the
  file mode — and a default umask of 022 creates `.ranbval.local` as `0644`, readable by every
  user on the box. `ssh` refuses a private key in that state; Ranbval was silent about it.

  `load_ranbval()` now warns when a file holding a `*_PROJECT_SECRET` is group/other-readable,
  naming the exact fix:

  ```
  Ranbval: .ranbval.local is 0644 — your project secret is readable by other users on this
  machine, and that key unseals every token in .ranbval. Fix it with:
      chmod 600 .ranbval.local
  ```

  It warns rather than raises, because `0644` is what the OS default produces rather than
  something you did wrong, and failing on upgrade would break working installs over a
  pre-existing condition. Set `RANBVAL_STRICT_FILE_MODE=1` to make it an error — worth doing in
  CI and production images. POSIX only; Windows does not express access this way.

- **`ranbval init` now creates `.ranbval.local` at `0600`.** Previously it created only
  `.ranbval` and left users to write the root-key file by hand, under whatever umask was in
  effect. The file is opened with mode `0600` directly rather than created and then `chmod`ed, so
  it is never briefly world-readable while already holding the secret. An existing file is left
  untouched.

- **The stdout guard now catches a secret however it was formatted.** It previously tested the
  *type* — so `print(key.use())` raised, but `print(f"{key.use()}")` and
  `print("Bearer " + key.use())` sailed through, because formatting a secret produces an ordinary
  `str` carrying no marker at all.

  That gap cannot be closed at the source: `__format__` must return the real value or no client
  library can build `Authorization: Bearer <key>`, and `str` is immutable so `str.__add__` cannot
  be intercepted. The guard now checks the **destination** — every value a `.use()` reveals is
  registered, and anything heading for stdout is checked against them:

  ```python
  print(f"{key.use()}")                # PermissionError
  print("Bearer " + key.use())         # PermissionError
  print({"api_key": f"{key.use()}"})   # PermissionError — nested, still caught
  print("ordinary output")             # fine
  ```

  While the guard is installed the registry holds each revealed plaintext for the life of the
  process — `str` subclasses cannot be weak-referenced, so a value cannot be tracked without being
  kept. Nothing is retained while it is off. Added `uninstall_output_guards()` to restore the
  originals and drop everything held. Values under 8 characters are not tracked; below that a
  "secret" collides with ordinary output more often than it matches one.

  See **Breaking** above for the default and for stderr/truncation coverage.

- **`install_output_guards()` / `uninstall_output_guards()` are exported at the top level.** The
  README documented `install_output_guards()` by that name, but it was reachable only as
  `ranbval_sdk.crypto.install_output_guards` — the documented call raised `ImportError`.

- **`ranbval check` reports a loose root-key file as an error** (exit 1), so a CI job or
  pre-commit hook fails on it rather than merely printing a warning nobody reads.

### Changed

- **Documented the threat model honestly.** A new README section, *What Ranbval protects, and what
  it does not*, states plainly that the project secret is plaintext and cannot be otherwise; that
  what Ranbval changes is the blast radius, not the existence of a root key; and that the
  in-process guards are tripwires rather than walls (`f"{val}"` returns the plaintext, because a
  client library must be able to build a header from it). `PROXY_` is identified as the only
  mechanism here offering a guarantee rather than a deterrent.

- **Corrected the overstated allowlist claims.** Five places presented the repo allowlist as
  though it were always active: the header ("a stolen config is useless off your allowlisted
  repos"), the architecture section ("the allowlist check is always on"), the leak-comparison
  table, the "crown jewel … a stolen config is a dead config" paragraph, and the house-key
  analogy. The
  policy is always *fetched* and cannot be bypassed client-side, but it only *blocks* a decrypt
  when `enforce_allowlist` is turned on for the project — and that is **off** by default. With it
  off, `.ranbval` plus `.ranbval.local` copied to any machine opens every token. Both statements
  now say so, and the README points at enabling the allowlist as the single highest-value action.

---

## [3.7.0] - 2026-07-28

The theme of this release is that **security you have to switch off isn't security**. Three of the
four changes below exist because the previous defaults were reliably pushing people into
`set_enforcement(False)` for the whole process.

### Added

- **`use` — one word per secret.** `use.NAME` loads `.ranbval` on first touch, resolves the prefix,
  decrypts, caches, and returns a value a client library can take directly. The whole program:

  ```python
  from ranbval_sdk import use
  from supabase import create_client

  supabase = create_client(use.SUPABASE_URL, use.SUPABASE_TOKEN)
  ```

  Write the **short** name — `SECRET_`, `PUBLIC_` and the bare spelling are tried in turn, so
  changing a key's prefix in `.ranbval` doesn't break your code. A miss raises `MissingKeyError`
  naming every spelling it tried, never a silent `None`.

  Shorter code, not weaker code: the value is still sealed (masked `repr`, unpicklable,
  iteration/slicing/`str()` still raise), and every access is still audited. `PROXY_` secrets are
  **refused** — they are meant never to decrypt on your machine. `Use(mode="staging")` pins a stage.

- **`enforcement_scope()`** — relax the extraction guards for one block and restore whatever was set
  before, instead of switching them off for the life of the process:

  ```python
  with enforcement_scope(False):        # the only unguarded window
      client = SomeClient(use.API_KEY)
  # strict again for every other line
  ```

  *Honest limit:* enforcement is a single process-wide flag, so the window is process-wide for its
  duration too — this is not thread-local isolation.

- **`ranbval_httpx_client()` / `RanbvalProxyTransport`** (`ranbval_sdk.integrations.httpx_transport`)
  — run a real client library through the secure proxy. Previously `proxy_request()` kept a `PROXY_`
  secret off the machine but only spoke raw HTTP, so you had to give up the library and hand-roll
  requests. Now:

  ```python
  supabase = create_client(
      url, "unused-placeholder",
      options=ClientOptions(httpx_client=ranbval_httpx_client(
          token=proxy_token("PROXY_SUPABASE_TOKEN"), inject_as="header:apikey")),
  )
  supabase.table("profiles").select("*").execute()   # normal call, key never local
  ```

  Stronger than any enforcement setting: there is no plaintext in the process to guard. Works with
  anything accepting a custom `httpx` client (`supabase`, `openai`, …). Not applicable to streaming
  or websocket transports, nor to libraries on raw sockets (`psycopg2`, `redis`).

### Changed

- **`.encode()` is now audited rather than blocked.** It is recorded in the audit log and seen by
  the access monitor, but no longer raises. `set_strict_encode(True)` restores the old behaviour.

  *Why.* The guard bought no secrecy: `f"{val}"` and `"{}".format(val)` already return the full
  plaintext through `__format__` — with no guard and not even a monitor event. Anyone after the
  value writes the f-string. Meanwhile `httpx` calls `value.encode("ascii")` on every header value
  it builds, so the guard's one reliable effect was to make working code impossible without
  `set_enforcement(False)` process-wide — disabling the guards that *do* work, permanently. A guard
  that reliably causes security to be switched off is worse than no guard.

  Every other guard is untouched: iteration, slicing/indexing, `str()`/`print()`, and `_buf`/`_pad`
  reads still raise `RanbvalSecurityError`.

- **`set_enforcement(False)` is no longer the documented remedy** for a library that trips a guard.
  Use `enforcement_scope(False)` around the handoff line. The process-wide switch remains for
  compatibility.

### Testing

- CI now covers **every supported interpreter on every supported OS** — Python 3.10–3.14 across
  Ubuntu, macOS and Windows (15 jobs, `fail-fast: false`). Previously only 3.10–3.12 on Ubuntu ran,
  while the package claimed 3.13 support and "OS Independent"; `crypto/memory.py` selects its
  `mlock` syscall per platform, so the OS axis exercises genuinely different code.
- Added an advisory **3.15-dev** job (`continue-on-error`) to catch CPython breakage early without
  blocking PRs, and a **`wheel-install`** matrix that installs the built artifact — with no source
  checkout present — and smoke-tests `import ranbval_sdk` plus the `ranbval` CLI on the full grid.
- Python 3.14 added to the classifiers.

---

## [3.6.0] - 2026-07-20

### Added

- **`plan_status()`** — what plan a project is on, what it allows, and how much of it is used this
  month. Authenticated with the credentials the SDK already has (`project_secret` or `api_key`);
  a `null` limit means unlimited on that plan.

  ```python
  from ranbval_sdk import plan_status

  s = plan_status(project_secret="ps_...")
  s["plan"]                          # "free"
  s["limits"]["requests_month"]      # 1000
  s["usage"]["requests_remaining"]   # 588
  s["enforced"]                      # False while billing is switched off
  ```

- **`PlanLimitError`** — raised instead of `ProxyError` when a proxied call is refused because the
  plan's allowance is spent (HTTP 429/402). Carries `used`, `limit`, `period`, `plan` and `kind` as
  fields rather than a stringified dict, so a caller can back off or upgrade rather than retry:

  ```python
  from ranbval_sdk import PlanLimitError

  try:
      proxy_request(...)
  except PlanLimitError as e:
      log.warning("%d/%d requests used this %s", e.used, e.limit, e.period)
  ```

  It subclasses `RanbvalError`, so existing `except RanbvalError` blocks keep working.

### Note on enforcement

The SDK reports limits; it does not apply them. It runs on the customer's machine, so any check it
performed locally could simply be removed — every limit is enforced server-side, on the call itself.
`plan_status()` exists for visibility (usage in your own tooling, a warning before a batch job), not
as a pre-flight permission check: there is nothing to gain by calling it first, and nothing lost by
skipping it.

---

## [3.5.4] - 2026-07-18

### Added
- **Commit-safety guard.** `load_ranbval()` refuses to run (`RanbvalConfigError`, code
  `secret_file_committable`) if a `.ranbval*` file holding a `*_PROJECT_SECRET` line is **not
  git-ignored** — the root key must never be one `git add` from a public repo. Verified with
  `git check-ignore` (honours global/nested/negated rules). Also catches the mistake of leaving the
  secret line in the committed `.ranbval`. Silent outside a git repo. Override with
  `RANBVAL_ALLOW_COMMITTABLE_SECRET=1`.

## [3.5.3] - 2026-07-14

### Fixed
- **`load_ranbval(environment=…)` selected the wrong stage for local files.** `environment` was
  read only on the remote path, so a local call silently fell back to `development` and loaded the
  wrong stage — no error, wrong values. It now selects the stage for local files too (`mode` remains
  the older alias, and wins if both are given).
- **Telemetry could be lost on a fast process exit.** The first use of a credential was dispatched
  on a daemon thread that the interpreter kills at shutdown, so a short-lived process
  (`python -c "…decrypt…"`) dropped the event — exactly the smash-and-grab a canary must catch.
  In-flight telemetry is now joined at exit (bounded), so the canary alert fires even on a one-liner.

## [3.5.2] - 2026-07-13

### Fixed
- **The `Documentation` link on PyPI was a 404** — it pointed at `api.secret.ranbval.com/docs`,
  which the API deliberately does not serve. It now points at the README.

### Added
- Package **keywords** (there were none, so PyPI search never surfaced the project) and a fuller
  classifier set; `Bug Tracker`, `Changelog`, and `Company` project links.
- A summary that says what the library actually does.

## [3.5.1] - 2026-07-13

### Changed
- Remote environment selection now uses the **same** chain as the local mode:
  explicit `environment=` → `RANBVAL_ENV` → `ENVIRONMENT` → `ENV`. One variable means one thing
  ("which stage am I running in") whether the config comes from disk or the control plane. There
  is deliberately no `development` default remotely — unset means "the project's first environment".

### Docs
- README documents environments (stages), stage selection, and `push_env(environment=…)`.

## [3.5.0] - 2026-07-13

### Added
- **Environments (stages).** A project now holds up to 10 named environments — `development`,
  `staging`, `production`, … — and every key and `PUBLIC_` value lives in one of them. Pull a
  single stage:

  ```python
  load_ranbval(remote=True, environment="production")   # or set RANBVAL_ENV=production
  ```

  `fetch_env_set(..., environment=...)` and `push_env(..., environment=...)` take the same
  argument. Selection falls back to the `RANBVAL_ENV` variable, then to the project's first
  environment — so existing code keeps working unchanged.

  The same name (`SECRET_OPENAI_KEY`, `PUBLIC_DATABASE_URL`) now resolves to a different value per
  stage, and a development machine never receives production credentials.

## [3.4.1] - 2026-07-13

### Fixed
- README refreshed for PyPI: version badge (was showing 2.2.1) and outdated `[public]`/`[secrets]`
  section docs replaced with the prefix-classification model (`PUBLIC_`/`SECRET_`/`PROXY_`).

## [3.4.0] - 2026-07-13

### Changed
- **Default API host moved to `https://api.secret.ranbval.com`** (was `https://api.ranbval.com`).
  The Ranbval secret manager now lives under the `secret.ranbval.com` namespace. Override with
  `RANBVAL_HOST` if needed. Set `RANBVAL_HOST` explicitly to pin the old host during transition.

---

## [3.3.1] - 2026-07-10

Internal restructuring + repo hygiene. **No public API or behaviour change** — every symbol,
import path, and error class is preserved (verified by the full test suite).

### Changed (internal)
- **`crypto.secret_string` split** (530 → 323 lines) into cohesive modules: `crypto/memory.py`
  (mlock), `crypto/enforcement.py` (extraction guards + reveal notifier), `crypto/output_guards.py`
  (opt-in print patching). `crypto/__init__` re-exports the same public API.
- **`cli` is now a package** — one module per command (`cli/init.py`, `cli/check.py`,
  `cli/run.py`) + `cli/_shared.py`. Console entry point `ranbval` unchanged.
- **`exceptions` is now a package**, grouped by subsystem (`base`, `config`, `crypto`, `policy`,
  `proxy`) and re-exported from `exceptions/__init__` — `from ranbval_sdk.exceptions import …`
  is identical.

### Docs / repo
- Moved `security_demo.py` → `examples/security_demo.py`.
- Updated `.ranbval.example` to the v3 prefix format (`PUBLIC_`/`SECRET_`/`PROXY_`).
- Hardened `.gitignore` (venv variants, coverage, editor/OS files, defensive `.ranbval`/`.env`).

---

## [3.3.0] - 2026-07-10

### Added
- **Developer role for remote config.** `load_ranbval(remote=True, api_key="ranbval-dev-…")` lets
  a developer (not just the owner) fetch the project's env-set with a developer token the owner
  issues from the dashboard. `project_secret` = owner; `api_key` = developer.
- **`push_env(name, value, api_key=… | project_secret=…)`** — add a `PUBLIC_` env from code,
  attributed to the caller. `SECRET_`/`PROXY_` stay owner-only (created encrypted in the dashboard).
- `fetch_env_set` now accepts `api_key` alongside `project_secret`.

---

## [3.2.0] - 2026-07-10

### Added
- **Remote config** — `load_ranbval(remote=True, project_secret="ranbval-proj-…")` fetches the
  project's whole env-set from the Ranbval control plane instead of reading local files, then runs
  the **same** classification + crypto pipeline. `SECRET_`/`PROXY_` values arrive as encrypted
  `ranbval.*` tokens and are decrypted client-side exactly as from a file; `PUBLIC_` values are
  plaintext. `host=` overrides the control-plane URL.
- **`fetch_env_set(project_secret=…, host=…)`** — the low-level `{name: value}` fetch, in the new
  `ranbval_sdk.remote` package (a pure *source* — it decrypts nothing).

  Clean separation: remote only changes *where the config comes from*. `SecretString`,
  enforcement, and the prefix rules are untouched.

---

## [3.1.0] - 2026-07-10

### Added
- **`ranbval` CLI** (installed as a console script — `pip install ranbval-sdk` is enough):
  - `ranbval init` — write a starter `.ranbval` and gitignore `.ranbval.local`.
  - `ranbval check` — lint `.ranbval`: unclassified keys, `[section]` headers, competing `.env*`
    files / imported loaders, and prefix/value mismatches. Non-zero exit on errors (CI-friendly).
  - `ranbval run -- CMD …` — load `.ranbval` into the environment, then exec `CMD` (secrets only
    in that process, nothing on disk). Never prints a value.

  Dependency-free (argparse + stdlib).

---

## [3.0.0] - 2026-07-10

**Breaking.** Configuration is now classified by a **required name prefix**, and Ranbval enforces
that it is the **sole** config/secret loader. `[section]` headers are gone.

### Changed / Breaking
- **Prefix-based classification.** Every variable in a `.ranbval` file must start with one of:
  - `PUBLIC_…`  — plaintext config, read with `public("PUBLIC_…")`
  - `SECRET_…`  — encrypted; `decrypt_key("SECRET_…").use()` reveals it locally
  - `PROXY_…`   — encrypted; plaintext **never** on the client; `proxy_token("PROXY_…")` + proxy

  The class lives in the name, so it is visible at every reference — in the file, in `os.environ`,
  and in code. `RANBVAL_*` and `*_PROJECT_SECRET` are exempt (infrastructure keys).
- **`[public]` / `[secrets]` / `[proxy]` section headers are removed.** A `[section]` line now
  raises `RanbvalConfigError` (`code="section_not_supported"`).
- **Unclassified keys are rejected at load time** (`code="unclassified_key"`) — no more silent
  auto-detect. Rename `FOO` → `PUBLIC_FOO` / `SECRET_FOO` / `PROXY_FOO`.
- `decrypt_key` now also refuses a `PUBLIC_` key (`code="not_a_secret"`), matching how it already
  refuses `PROXY_`.

### Added
- **Sole-loader enforcement** (`load_ranbval(sole_loader=True)`, default on): raises if a
  competing `.env*` file sits beside your `.ranbval` (`code="competing_env_file"`), or if a
  dotenv-style library (`python-dotenv` / `decouple` / `environs` / `dynaconf`) is already
  imported (`code="competing_env_loader"`). Pass `sole_loader=False` to opt out.
  - **Honest limit:** a bare `os.getenv("X")` is ordinary Python and cannot be detected or
    forbidden — only competing *files* and *imported loaders* are caught.

### Migration
```
# before (v2)                     # after (v3)
[public]                          PUBLIC_DATABASE_URL=postgres://…
DATABASE_URL=postgres://…         SECRET_OPENAI_KEY=ranbval.…
[secrets]                         PROXY_STRIPE_KEY=ranbval.…
OPENAI_KEY=ranbval.…              RANBVAL_PROJECT_SECRET=ranbval-proj-…   # exempt
```

---

## [2.3.0] - 2026-07-09

Detection → **enforcement**. The extraction vectors 2.2.x only *reported* now **raise** by default.

### Added
- **Extraction enforcement, strict by default.** When a revealed value is manipulated in a way
  that signals in-memory theft, the SDK now raises `RanbvalSecurityError` instead of silently
  handing over the plaintext:
  - character-by-character **iteration** — `''.join(c for c in key.use())`, `list(...)`, comprehensions
  - **`.encode()`** to raw bytes
  - **slicing / indexing** — `val[:]`, `val[0]`, `val[1:5]`
  - a **buffer read** — `s._buf` / `s._pad`, now **including** the `object.__getattribute__(s, "_buf")`
    form that bypassed the class in 2.2.x (`_buf`/`_pad` are now honeypot properties; the real
    bytes live in the private `_b`/`_p` slots)
  - **`str()` / `print()` / `"%s" %`** — these now raise (loud) instead of returning the
    `[ranbval:secret]` mask. `repr()` still masks (so Sentry/debuggers don't crash), and with
    `set_enforcement(False)` `str()` masks as before.

  Legitimate paths are untouched: `f"Bearer {key.use()}"`, `"Bearer " + key.use()` concatenation,
  `.format()`, and the SDK's own internal decryption all keep working.
- **`set_enforcement(enabled)` / `is_enforced()`** — flip enforcement off process-wide if a
  legitimate library trips it (e.g. an AWS SigV4 signer or DB driver that must `.encode()` the
  credential). Off = the previous *detect + notify* behaviour.
- **`RanbvalSecurityError`** (subclass of `RanbvalError` + `PermissionError`), code
  `secret_extraction_blocked`, with `context["method"]` = `iteration` / `encode` / `slice` /
  `str` / `buffer_read`.

### Honest limit (unchanged)
Enforcement is a **naive-attacker deterrent, not a guarantee** — it turns silent theft into a
loud, alerting crash, and now catches the `str()`/`_buf`/slice/iterate spellings. Two floors
remain, and we deliberately do **not** fake-guard them: **the base `str` methods**
(`str.__str__(val)`, `str.__getitem__(val, ...)`, `str.encode(val)`, and `"x" + val`
concatenation) — the built-in `str` type is immutable so no library can override them, *and the
SDK depends on them* (a value libraries can format into a request is a value any code can read);
and **`object.__getattribute__(s, "_b")`** (the real slot, findable by anyone reading this
open-source file). The only absolute protection remains the **`[proxy]`** section, where the
plaintext never enters the client process.

---

## [2.2.1] - 2026-07-09

### Changed / Security
- **Closed the `_plaintext_bytes()` convenience bypass** — that internal method (which
  reconstructed the plaintext without going through `.use()`) is removed; reconstruction is now
  a module-level helper the class calls via `object.__getattribute__`, so there is no
  `secret.<method>()` an external caller can invoke to reveal a value.
- **Naive buffer reads are now flagged** — accessing `s._buf` / `s._pad` directly (a reveal-gate
  and monitor bypass) fires `secret.possible_exfil` (`method="buffer_read"`) to the access
  monitor / Live Monitor, then still returns the value. The SDK's own internals read the slots
  via `object.__getattribute__`, so they don't trip it.

  **Honest limit (unchanged):** an attacker using `object.__getattribute__(s, "_buf")` *directly*
  bypasses even this — that path is undetectable/unpreventable in-process for any tool. The only
  real protection for a secret that must never be reconstructable is the `[proxy]` section, where
  the plaintext never exists in the client process at all.

---

## [2.2.0] - 2026-07-09

Trusted-party controls: **restrict** where a secret may be revealed, and **detect** when it is.

### Removed
- **`RANBVAL_TELEMETRY_DISABLED` is gone** — usage reporting is the leak-detection control
  plane, so it is now **always on with no client-side off switch**. A disable flag would let an
  attacker (or a curious insider) turn off the very monitoring that catches misuse, which
  defeats the purpose. The developer-identity opt-in (`RANBVAL_TELEMETRY_IDENTITY=1`, off by
  default) remains — it only *adds* data (git email), never disables reporting.

### Added
- **Reveal scopes** — `require_reveal_scope("NAME")` + `with reveal_scope("NAME"): ...`. For a
  value your app must decrypt locally (a DB password, a signing key) but that you don't want an
  engineer to read anywhere else: restrict it so `decrypt_key("NAME").use()` returns the
  plaintext **only inside a `reveal_scope` block** — a `.use()` anywhere else raises
  `RanbvalConfigError` (`reveal_out_of_scope`). This shrinks the reveal surface from "any line,
  invisibly" to **one approved, greppable, reviewable block** you can enforce in CI. Thread-local
  (a scope on one thread never permits a reveal on another). `decrypt_key` / `safe_decrypt` now
  label the secret with its env-var name so scopes and the audit log can identify it.

  Honest limit: this gates `.use()` (the audited access point); it does not stop a determined
  insider who bypasses the class (reads the internal buffer, calls `str.__str__`) — unpreventable
  in-process for any tool. It makes the reveal *restricted and auditable*, not impossible.
- **Opt-in secret-access monitoring** — `install_access_monitor()`. A trusted party who can
  decrypt can always extract the plaintext (no library prevents that), so this makes the
  access **visible and attributable** on your Live Monitor instead:
  - Every `SecretString.use()` is classified by call context — `app` (a real `.py`),
    `exec` (`python -c`), `repl` (`<stdin>`), `notebook` (IPython). Anything but `app` is
    flagged `secret.suspicious_access` (a normal app never reveals a secret from a REPL).
  - **In-memory extraction is caught too:** `SecretString.use()` returns a `_ProtectedStr`
    whose `__iter__` and `encode()` are instrumented, so `''.join(ch for ch in key.use())` /
    `list(...)` / a comprehension (`method="iteration"`) and `key.use().encode()`
    (`method="encode"`) fire `secret.possible_exfil` **while still returning the real value**
    (nothing legitimate breaks; f-strings hit `__format__`, not these, so no false alarm —
    note `encode` can false-positive for HMAC-signing SDKs, and never blocks).
- **Memory-buffer obfuscation** — `SecretString` now stores the secret XOR-masked with a
  per-instance random pad, so reading the internal buffer directly
  (`object.__getattribute__(s, "_buf")`) yields only garbage instead of the plaintext. This
  closes the naive one-slot bypass and pushes any reader back through the gated, audited
  `.use()`. Bar-raising, not absolute (a determined insider can read both slots); `len` / `==`
  / `hash` / `wipe` are unchanged in behaviour.
  - With `watch_exfil=True` (default), a `sys.addaudithook` also flags a **file write** or a
    **subprocess** right after a `.use()` as `secret.possible_exfil`.
  - Signals go to the Live Monitor by default, or to your own `on_event` handler.

  **Honest limits (documented, not sold otherwise):** this is *detection, not prevention*,
  and *heuristic*. It catches the extraction methods that actually happen — `python -c`/REPL
  access, character iteration (`join`/`list`/comprehension), write-to-file, pipe-to-subprocess.
  It does **not** catch every conceivable path (e.g. calling `str.__str__(x)` directly, or
  reading the internal buffer via `object.__getattribute__`); those need a hardware enclave /
  OS taint-tracking. It is not a DLP/EDR replacement. New `crypto.audit.set_access_notifier`
  and `crypto.secret_string.set_reveal_notifier` hooks.

---

## [2.1.1] - 2026-07-09

### Fixed
- **`proxy_token()` is now section-aware.** It previously only checked the token *format*
  (a `ranbval.*` value), so it would happily return a token for a key declared under
  `[secrets]` or `[public]`. It now refuses those — a `[secrets]` key must be read with
  `decrypt_key().use()`, a `[public]` key with `public()` — which catches misuse such as
  passing a `[secrets]` database password to the HTTP proxy. `[proxy]` keys and unlabelled
  `ranbval.*` tokens are still accepted. This makes all three accessors own their section
  (`public()` → `[public]`, `decrypt_key()` → `[secrets]`, `proxy_token()` → `[proxy]`).

---

## [2.1.0] - 2026-07-09

### Added
- **`[proxy]` section** — a third `.ranbval` section for secrets whose plaintext must **never**
  reach the client. `decrypt_key()` **refuses** a `[proxy]` key (`RanbvalConfigError`, code
  `proxy_only`); the value is usable only via `proxy_request()`, where the real key is decrypted
  and injected on Ranbval's server. New helpers `proxy_token("NAME")` (returns the raw encrypted
  token to pass to the proxy) and `is_proxy("NAME")`. Header aliases: `[proxy]` / `[proxy-only]` /
  `[sealed]`. `public()` also refuses `[proxy]` keys, and `load_ranbval()` warns if a `[proxy]`
  value is plaintext.

  The three sections now express a visibility ladder:
  - `[public]` — plaintext, anyone may read (e.g. shown in a UI).
  - `[secrets]` — encrypted at rest; the app *can* decrypt and view/use it at runtime.
  - `[proxy]` — encrypted; plaintext never reaches the client (HTTP API keys, Stripe keys).

  Combine `[proxy]` with **not shipping `RANBVAL_PROJECT_SECRET` to that client** and it is
  cryptographically impossible for that environment to produce the plaintext at all.

  Fully backward compatible — sections remain optional.

---

## [2.0.0] - 2026-07-08

### Removed (breaking)
- **`secure_client()` and `build_secure_client()` are removed.** They implicitly assumed an
  OpenAI/Anthropic-shaped SDK (a class with an `api_key=` constructor kwarg plus a nested method
  to patch), so they did not fit providers with a different shape — e.g. Google Gemini
  (`genai.configure(api_key=...)`), AWS Bedrock (`boto3`), Vertex, and others. Ranbval is a
  **provider-agnostic secret manager**: decrypt the key and pass it wherever the provider wants it.

  **Migration** — replace the wrapper with a direct decrypt at the call site:

  ```python
  # before
  client = secure_client(openai.OpenAI, env_var="OPENAI_API_KEY", key_kwarg="api_key")

  # after — works for OpenAI, Anthropic, Gemini, Bedrock, raw HTTP, anything
  client = openai.OpenAI(api_key=decrypt_key("OPENAI_API_KEY").use())
  ```

  Usage is still auto-reported by `decrypt_key()`; nothing about telemetry or the security model
  changes. The `integrations/factory.py` and `integrations/universal.py` modules were deleted;
  the server-side `proxy_request()` / `aproxy_request()` remain.

---

## [1.4.1] - 2026-07-08

Hardening, privacy, and maintainability pass. **No breaking public-API changes** — every
`from ranbval_sdk import …` still works. One documented behaviour is now correct:
`build_secure_client(..., env_var=..., key_kwarg=...)` matches the README (the parameters were
previously named `env_var_name` and only worked positionally).

### Added
- **`[public]` / `[secrets]` sections** in `.ranbval` — declare unencrypted config
  (`DATABASE_URL`, `CORS_ORIGINS`, `PORT`, …) separately from encrypted vault tokens. New
  `public(name)` / `public_config()` / `is_public(name)` accessors return plaintext only and
  refuse to hand back a declared secret or a `ranbval.*` token. The same guarded access is
  available on the `Vault` / `env` object as `env.public(name)` / `env.public_config()`, so a
  secret can never be read through a public path on any access surface. `load_ranbval()` warns
  when a value contradicts its section. Fully backward compatible — sections are optional and
  flat files behave exactly as before. New `config/manifest.py`.
- **Telemetry privacy switches** — `RANBVAL_TELEMETRY_DISABLED=1` turns off all usage
  reporting; `RANBVAL_TELEMETRY_IDENTITY=1` opts in to sending `git config user.email`
  (now **off by default** — PII is not collected unless enabled). New `telemetry/settings.py`.
- **Structured errors** — `RanbvalError` now carries a machine-readable `.code` and a
  `.context` dict for logging/metrics without parsing message strings.
- **Repo-policy caching** — the per-decrypt allowlist fetch is cached per `(host, salt)` for
  60s, so hot decrypt loops no longer make one blocking HTTP round-trip per call.

### Changed
- **Pure-Python packaging** — removed the stale Cython build hook (`build.py`) and the
  `Cython`/`setuptools` build requirements. The SDK ships as a universal wheel + sdist that
  installs on any platform (previously only a macOS-arm64 wheel built, and it referenced a
  `crypto.py` that no longer exists). Obfuscation was never a security control.
- **`SecretString` refuses serialization** — `pickle`, `copy`, and `deepcopy` now raise
  `TypeError`, closing the real accidental-leak paths (error reporters like Sentry pickling
  local variables, celery/multiprocessing pickling task args, disk/redis caches). `.use()`
  values keep working inside SDKs (copy allowed for the immutable str; only pickle refused).
  Docstrings/README rewritten to describe the guarantees **honestly** — masking blocks
  accidental exposure; it is not a defense against deliberate reveals or process-memory
  attackers, and memory zeroing/`mlock` are best-effort, not guarantees.
- **`load_ranbval()` no longer patches global builtins by default** — the `print` /
  `sys.stdout.write` output guards are now opt-in via `load_ranbval(guard_stdout=True)`.
  `SecretString` still masks itself via `__str__`/`__repr__`. Removed the fragile
  frame-inspection f-string detection.
- **Honest crypto errors** — replaced pseudo-technical messages ("packet fragmentation",
  "signature matrix") and the hard-coded `"ahsan"` label check with clear, actionable
  messages. The token `<label>` is now treated as an opaque tag (so labels like `stripe`
  work), and token parsing/TTL handling is factored into small tested helpers.
- **Auto-patched SDK telemetry** now flows through the same adaptive sampler as
  `decrypt_key()` instead of spawning a thread + POST on every call.
- **Deprecation via `warnings.warn`** — `RANBVAL_VAULT_SECRET` deprecation uses
  `DeprecationWarning` instead of printing to stderr.
- **Consistent style** — modern `X | None` type hints, sorted imports, and `ruff` + `mypy`
  configuration added to `pyproject.toml`. `MissingKeyError` no longer double-quotes its
  message (the classic `KeyError.__str__` gotcha).

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
