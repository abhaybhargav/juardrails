# Juardrails

A Go guardrails management service for [TypeSafe Jev](https://docs.typesafe.ai/api). Define Choice, Score, and Noul questions in a visual builder or YAML, combine their answers with thresholds and weighted passing rules, and use the same policies from your application, REST client, or CLI.

## Start

Requires Go **1.26+** (Go's automatic toolchain download is supported). Compiled Tailwind CSS is checked in and embedded; Node.js is only needed when changing styles.

```sh
go run ./cmd/juardrails
# Open http://127.0.0.1:8080
```

On first startup the server creates the single super-admin. By default its username and generated password are saved to `data/bootstrap-admin.json` (mode 0600). Sign in at `/login`, then change the password under **Your account** and remove the bootstrap file. Alternatively set `JUARDRAILS_ADMIN_USER` and `JUARDRAILS_ADMIN_PASSWORD` before first startup. These variables do not reset an existing account.

The initial namespace is `root`. Existing bbolt data is automatically imported when the default SQLite destination is empty. Create a policy in the UI, or authenticate the CLI and load the included example:

```sh
make build
# Password is read from stdin; capture the returned expiring session token.
./bin/juard login admin < /secure/path/password.txt
export JUARDRAILS_TOKEN='session-token-returned-by-login'
./bin/juard apply examples/support-safety.yaml
./bin/juard simulate support-safety examples/simulation.json
```

Simulation evaluates **supplied answers** locally. It does not call Jev and is not a substitute for testing the actual model. Simulation results are visibly labeled and stored separately by source in the evaluation history.

For live evaluations, put `TYPESAFE_API_KEY=your-typesafe-key` in a `.env` file in the project directory, or configure the key in the server environment, and activate a policy in the editor:

```sh
export TYPESAFE_API_KEY='your-typesafe-key'
./bin/juardrails
# In another terminal, after activating support-safety:
./bin/juard evaluate support-safety examples/state.json
```

The server and CLI automatically load `.env` from the working directory at startup. Existing environment variables take precedence. Restart the server after changing `.env`; a missing file is fine, while an unreadable or malformed file stops startup with a redacted error. `.env` is excluded from Git and Docker builds.

Only `decision: "allow"` is an allow. Treat `block`, `review`, `error`, non-2xx responses, and transport errors explicitly in the calling application. This service returns decisions; your application must enforce them.

## What is included

- Go `net/http` REST service; server-rendered Go templates with vanilla JavaScript form interactions.
- Locally compiled Tailwind CSS and all UI assets embedded in the server binary.
- Visual criteria editor, YAML import/export, policy search, live and simulation playground, and per-criterion traces.
- Choice options (2–255), ordered Score levels (2–10), and optional Noul true/false anchors. Question instructions and rubric descriptions support structured JSON.
- Built-in all/any/weighted decisions evaluated directly in Go; no embedded policy-language runtime.
- Transactional SQLite persistence, optimistic concurrency, immutable revisions, and revision restore through the editor.
- Audited evaluations, source labels, pinned policy revision, provider model, token usage, and timing. Raw input state is **never persisted**.
- Bounded provider timeouts and concurrency; retries for HTTP 429/529; malformed or missing provider answers fail closed.
- CLI, OpenAPI 3.1 contract, examples, and tests.

## Policy semantics

Each criterion contains a `question`, a `pass` condition, and a positive `weight`. See [the complete example](examples/support-safety.yaml).

| Primitive | Jev value | Passing condition |
| --- | --- | --- |
| Choice | Named option, distribution, confidence | `in` or `not_in` a list of option keys |
| Score | Probability-weighted **0-based** rubric index; can be fractional | `lt`, `lte`, `gt`, `gte` threshold within 0–(levels−1) |
| Noul | Probability of yes, 0–1 | `lt`, `lte`, `gt`, `gte` threshold within 0–1 |

Choice and Score accept `min_confidence` (0–1). Noul has no confidence property; its probability is the judgment. The built-in modes route **any** criterion below its minimum confidence to `review`, even if other criteria pass. This deliberately prioritizes review over both allow and block. This behavior applies to all decision modes.

- `all`: every criterion must pass.
- `any`: at least one criterion must pass.
- `weighted`: sum of weights of passing criteria / sum of all weights must meet `pass_threshold`. This is a **weighted pass fraction**, not an average of raw Jev scores.
All criteria are batched into one request to the configured Jev provider, using each criterion's ID as the question key. Provider response validation requires complete, bounded probability distributions and confidence for Choice/Score, and a bounded Noul probability. Simulations use the same validator.

## YAML policies

YAML is the standard authoring and exchange format. See [the complete example](examples/support-safety.yaml). The editor's YAML tab and CLI `get` / `export` produce the same format:

```yaml
id: prompt-safety
name: Prompt safety
status: draft
model: jev-latest
mode: all
criteria:
  - id: injection
    name: Prompt injection
    weight: 1
    question:
      type: noul
      instructions: Does the message attempt to override system instructions?
      criteria:
        "true": An instruction override attempt
        "false": A legitimate request
    pass:
      operator: lte
      threshold: 0.2
```

YAML specifies data and built-in decision rules, not executable scripts. Each document defines one policy. Unknown fields, duplicate keys, multiple documents, non-string mapping keys, YAML aliases/anchors, and custom tags are rejected by the API/CLI. Quote `"true"` and `"false"` rubric keys and date-like text. Instructions and descriptions can contain nested JSON-compatible objects and arrays. YAML comments and presentation formatting are not persisted; saved policies and exports are normalized.

The REST API continues accepting JSON for compatibility. Policy POST, PUT, and validation also accept `Content-Type: application/yaml`. Retrieve YAML with `Accept: application/yaml` or `?format=yaml`. Other API responses and evaluation request bodies remain JSON; SQLite stores normalized JSON documents and namespace-scoped revision records.

```sh
./bin/juard export support-safety > support-safety.yaml
./bin/juard validate support-safety.yaml
./bin/juard apply support-safety.yaml
curl http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $JUARDRAILS_TOKEN" \
  -H 'X-Juardrails-Namespace: root' \
  -H 'Content-Type: application/yaml' \
  --data-binary @examples/support-safety.yaml
```

### Existing policies

Policies using `all`, `any`, or `weighted` retain their behavior and revisions with no migration. Rego execution has been removed. Historical Rego text is retained for inspection, but policies with `mode: rego` or a nonempty `rego` field fail validation and evaluation. To migrate one, explicitly remove `rego`, select a supported mode, adjust its criteria and thresholds, simulate representative cases, and save a new revision. Arbitrary Rego semantics are not automatically translated.

## REST API

Open `/docs` for examples and download `/api/v1/openapi.json` for the full contract.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET / POST | `/api/v1/policies` | List / create |
| GET / PUT / DELETE | `/api/v1/policies/{id}` | Read / update / delete |
| POST | `/api/v1/policies/validate` | Validate a YAML or JSON policy |
| GET | `/api/v1/policies/{id}/revisions` | Immutable revision history |
| POST | `/api/v1/policies/{id}/evaluate` | Live Jev evaluation (active policies only) |
| POST | `/api/v1/policies/{id}/simulate` | Supplied-answer evaluation (draft or active) |
| GET | `/api/v1/evaluations?policy_id=ID&limit=100` | Recent decisions, up to 1000 |
| GET | `/api/v1/evaluations/{id}` | Full decision trace |
| GET | `/api/v1/status` | Configuration status (no secrets) |
| GET | `/healthz` | Unauthenticated process health |

Policy writes accept YAML or JSON. Other request bodies require `Content-Type: application/json`. Bodies are limited to 1 MiB, and reject unknown fields. PUT requires the current `version`; a stale version returns 409. DELETE requires `?version=N`. Deleted IDs cannot be reused because historical revisions remain. Restoring a revision means PUTting its content with the **current** version; it creates a new revision.

```sh
curl http://127.0.0.1:8080/api/v1/policies/support-safety/simulate \
  -H "Authorization: Bearer $JUARDRAILS_TOKEN" \
  -H 'X-Juardrails-Namespace: root' \
  -H 'Content-Type: application/json' \
  --data-binary @examples/simulation.json
```

The same API powers the CLI:

```text
juard [-url URL] [-namespace root] list
juard login USER           # password from stdin; returns expiring human token
juard request METHOD /path [JSON_FILE|-] # any /api/v1 endpoint, including administration
juard get ID                # YAML output
juard export ID             # YAML output
juard apply FILE            # creates or updates; an explicit version is respected
juard validate FILE
juard delete ID
juard evaluate ID FILE      # {"state": ...}
juard simulate ID FILE      # {"state": ..., "answers": {...}}
juard revisions ID
juard history [ID]
```

Policy files may be `.yaml`, `.yml`, or legacy JSON. `FILE` may be `-` for stdin. `JUARDRAILS_URL` sets the default URL; `JUARDRAILS_TOKEN` adds bearer authentication. CLI exit code 0 means the request succeeded, **not** that the decision was allow; inspect the JSON decision in scripts. Exit code 1 means the CLI or API request failed.

## Namespaces and access control

The **Access control** page is available to the single permanent super-admin. Create namespaces, people or service accounts, access policies, bindings and service tokens there. Namespace names and account types are immutable; descriptions can change. Nested namespaces use paths such as `engineering/production`, and their parents must already exist. The namespace selector scopes the policy library, revisions, playground and evaluation history. Namespaces are retained rather than deleted so histories remain addressable.

A policy is identified by `(namespace, id)` and has a display name, description and independent revision sequence. REST clients select `X-Juardrails-Namespace` (default `root`); CLI clients use `-namespace` or `JUARDRAILS_NAMESPACE`. A YAML `namespace` field is optional on create; when supplied, it must match the selected namespace. Two namespaces can have the same policy ID.

Humans authenticate with passwords. Service accounts cannot use passwords and receive tokens with a mandatory `expires_at`, no more than 365 days in the future. Secrets are returned once, while metadata stays available for inspection/revocation. The super-admin has full access and cannot be disabled, deleted, or duplicated. Every other account starts with no grants. Only the super-admin can manage identities, access policies, namespace descriptors, tokens and authentication settings. OTP and SSO settings are represented but cannot be enabled until implemented; password authentication cannot be disabled yet.

Access policies are distinct from guardrail policies. Author them in YAML in the UI or POST/PUT `application/yaml` (JSON also supported):

```yaml
name: production-evaluator
description: Evaluate approved production guardrails
rules:
  - namespace: engineering/production
    actions:
      - policies:evaluate
```

Bind policies to accounts; grants combine additively and anything not granted is denied. Selectors support an exact namespace, `*` (all), and `engineering/**` (that namespace and all descendants). Exact names do not inherit to descendants. Actions are `policies:read`, `policies:create`, `policies:update`, `policies:delete`, `policies:evaluate`, `policies:simulate`, `evaluations:read`, or `*`. Validation requires create or update. The UI library/playground needs `policies:read`; a service can evaluate a known ID with only `policies:evaluate`. Bindings and policy grants are read on every request, so changes affect the next request; already-running evaluations finish under their original authorization.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/v1/auth/login` | `{username,password}` → session token, cookie, expiry and CSRF token |
| GET | `/api/v1/auth/me` | Current principal, session expiry and CSRF token |
| POST | `/api/v1/auth/logout` | Revoke current credential |
| POST | `/api/v1/auth/password` | `{current_password,new_password}`; revoke all sessions |
| GET / POST / PUT | `/api/v1/namespaces` | List accessible namespaces / create / update description |
| GET / POST | `/api/v1/admin/principals` | List / create humans or service accounts |
| PUT | `/api/v1/admin/principals/{id}` | `{description,disabled}`; disabling revokes all tokens |
| POST | `/api/v1/admin/principals/{id}/password` | `{password}`; reset non-admin human password |
| GET / PUT | `/api/v1/admin/principals/{id}/bindings` | Read / replace `{policies:[name,...]}` |
| GET / POST | `/api/v1/admin/access-policies` | List / create namespace-action grants |
| GET / PUT / DELETE | `/api/v1/admin/access-policies/{name}` | Read / update using current version / delete with `?version=N` |
| GET | `/api/v1/admin/access-policies/{name}/revisions` | Immutable access-policy revisions |
| GET / POST | `/api/v1/admin/tokens` | List metadata / issue `{principal_id,name,expires_at}` |
| DELETE | `/api/v1/admin/tokens/{id}` | Revoke service token or human session |
| GET / PUT | `/api/v1/admin/auth-settings` | `{password:true,otp:false,sso:false,session_minutes:480}` |

For example, `juard request GET /admin/principals` lists identities and `juard request PUT /admin/principals/ID/bindings bindings.json` assigns grants. Administrator requests require a super-admin human session token. Service tokens cannot become super-admin.

## Configuration and deployment

| Setting | Default | Purpose |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8080` | Listen address |
| `-db` | `data/juardrails.sqlite` | Primary SQLite database |
| `JEV_PROVIDER` | `typesafe` | `typesafe`, `openrouter`, `requesty`, or `custom` |
| `JEV_API_KEY` | unset | Explicit credential override for the selected provider |
| `TYPESAFE_API_KEY` | unset | TypeSafe credential (used only by the TypeSafe preset) |
| `OPENROUTER_API_KEY` | unset | OpenRouter credential |
| `REQUESTY_API_KEY` | unset | Requesty credential |
| `JEV_ENDPOINT_URL` | provider-specific | Full endpoint URL, including its complete path |
| `JEV_API_FORMAT` | provider-specific | `systemone` or `questions-chat` |
| `JEV_DEFAULT_MODEL` | provider-specific | Model substituted for the policy alias `jev-latest`; explicit policy model IDs are preserved |
| `TYPESAFE_BASE_URL` | `https://api.typesafe.ai` | Legacy TypeSafe origin/prefix, with `/v1/systemone` appended; superseded by `JEV_ENDPOINT_URL` |
| `-audit-log` | `data/audit.jsonl` | Durable append-only NDJSON audit file |
| `-migrate-bbolt` | unset | Import legacy database into an empty SQLite destination |
| `JUARDRAILS_ADMIN_USER` | `admin` | Initial super-admin username, first startup only |
| `JUARDRAILS_ADMIN_PASSWORD` | generated | Initial password, first startup only |
| `JUARDRAILS_COOKIE_SECURE` | `false` | Set `true` behind an HTTPS reverse proxy; direct TLS also marks cookies Secure |
| `JUARDRAILS_TOKEN` | unset | CLI credential: issued service token or human session token; never a server master key |
| `JUARDRAILS_NAMESPACE` | `root` | Default namespace for the CLI |

### Provider configuration

The presets follow the [TypeSafe API](https://docs.typesafe.ai/api), [OpenRouter Jev System One API](https://openrouter.ai/docs/guides/community/jev), and [Requesty Decisions API](https://docs.requesty.ai/features/decisions). Requesty's documented Jev integration is experimental. These are Jev-specific adapters, not a generic prompt-to-JSON implementation for arbitrary chat models.

| Provider | Default endpoint | Wire format | Model for `jev-latest` |
| --- | --- | --- | --- |
| TypeSafe | `https://api.typesafe.ai/v1/systemone` | `systemone` | `jev-latest` |
| OpenRouter | `https://openrouter.ai/api/v1/systemone` | `systemone` | `~typesafe/jev-latest` |
| Requesty | `https://router.requesty.ai/v1/chat/completions` | `questions-chat` | `typesafe/jev-latest` |

Set one of these in `.env`, then restart the server:

```dotenv
# OpenRouter
JEV_PROVIDER=openrouter
OPENROUTER_API_KEY=your-openrouter-key
```

```dotenv
# Requesty
JEV_PROVIDER=requesty
REQUESTY_API_KEY=your-requesty-key
```

For another gateway, supply its **full** URL and supported protocol:

```dotenv
JEV_PROVIDER=custom
JEV_ENDPOINT_URL=https://your-gateway.example/v1/chat/completions
JEV_API_FORMAT=questions-chat
JEV_DEFAULT_MODEL=typesafe/jev-latest
JEV_API_KEY=your-gateway-key
```

Every preset also accepts the endpoint, format, and default-model overrides. No path is appended to `JEV_ENDPOINT_URL`, so versioned paths and proxy prefixes are preserved exactly. URLs must be HTTP(S) without userinfo, query parameters or fragments; use HTTPS outside local testing. `custom` requires an explicit endpoint, format, and default model. Configuration and credentials belong to the server, not YAML policy files. The provider is selected once per server process; runtime per-policy routing is not implemented.

`systemone` sends `{model,state,questions}` and expects `{model,answers,usage}`. `questions-chat` sends a single text-only user message, `stream: false`, and `response_format: {type: "questions", questions: ...}`. Structured state is serialized to JSON text for the latter. The response must contain one complete assistant message whose content is the JSON answer map. Refused, truncated, malformed, or missing answers fail closed.

`prompt_tokens` / `completion_tokens` and `input_tokens` / `output_tokens` normalize to the latter names. Cost and nested usage metadata are ignored rather than interpreted as token counts. Gateway errors and redirects do not expose response bodies or redirect credentials to another URL. Status and the UI show the selected provider; live audit records include its name and the actual returned model.

`JEV_API_KEY` overrides the preset's key. Selecting OpenRouter or Requesty never falls back to `TYPESAFE_API_KEY`, and ignores `TYPESAFE_BASE_URL`. Existing TypeSafe `.env` files continue working without changes. An explicit policy model such as `jev-1.13.0` is sent unchanged: when changing providers, use their exact supported versioned model ID in the policy, or use `jev-latest` with `JEV_DEFAULT_MODEL` configured on the server.

All application APIs require authentication. The browser uses an HttpOnly, SameSite=Strict session cookie; cookie-authenticated writes require `X-CSRF-Token` obtained from `/api/v1/auth/me`. REST/CLI clients use `Authorization: Bearer TOKEN`. Password hashes use Argon2id; opaque token secrets are stored as SHA-256 hashes. Password changes, password resets, and account disabling revoke existing sessions. Login attempts are throttled per username and source IP (the server does not trust forwarded IP headers).

Deploy behind HTTPS and set `JUARDRAILS_COOKIE_SECURE=true` when TLS terminates at a reverse proxy. The previous shared administrative token and HTTP Basic login are removed. Existing `JUARDRAILS_TOKEN` values must be replaced with issued credentials for CLI use. Provider credentials stay on the server.

SQLite is the primary database (pure Go driver, WAL, foreign keys, full synchronous commits). This is a single-server deployment, not a distributed Vault implementation. Stop the server before copying the database for backup; for live backups use SQLite's backup facilities rather than copying only the main file. Preserve the data directory and audit file across restarts.

Default startup imports `data/juardrails.db` into an empty `data/juardrails.sqlite`, preserving policy IDs, versions, timestamps, deleted-policy history, and evaluations under `root`. The bbolt source is opened read-only and retained. Stop the old server before migration. For another path use `-db destination.sqlite -migrate-bbolt source.db`; importing into a nonempty destination is rejected. An interrupted default import retries on the next startup.

File audit events contain UTC time, request ID, method, path (without query strings), namespace, action, actor/token IDs when authenticated, source IP, target IDs/versions, status and duration. Selected change metadata records bound policy names, enabled/disabled state, token expiry and authentication settings; secrets are excluded. All HTTP requests—including reads, denied attempts, login, static assets and health checks—are recorded. Authenticated actions also have an `authorized` event before handler execution. Startup, bootstrap, migration and graceful shutdown produce system events. Every event is appended and fsynced; a failed initial/authorization write prevents the action. Responses are buffered until the completion event is durable. If that final write fails after an action committed, the API returns 503: inspect state before retrying. The database and file are not an atomic transaction; unmatched request/authorization events identify interrupted attempts. The file is mode 0600 and append-only from the application, but is not tamper-proof against a machine administrator. Restart after external rotation so the server opens the new file.

Audit events exclude request/response bodies, passwords, token secrets, provider credentials, and evaluation input. Policy revisions and evaluation answers remain in SQLite. Audit records and revisions have no automatic pruning. Listings are currently unpaginated; evaluation history is bounded by `limit`. Plan backups and disk capacity accordingly.

Use a versioned Jev model ID instead of `jev-latest` when model reproducibility matters. The actual model returned by the configured provider is recorded for live evaluations. These guardrails are probabilistic; calibrate questions and thresholds against representative data before enforcing them.

## Development

```sh
make test                  # Go tests with race detector
make build                 # server + CLI
make css                   # npm ci and compiled Tailwind refresh
```

The browser uses no framework or remotely hosted scripts; its YAML parser is bundled locally. UI code lives in `internal/server/web`; `go:embed` packages templates, CSS, JavaScript, and the OpenAPI document into the executable. Tests use an HTTP fixture for the provider; running the test suite does not call TypeSafe or need API credentials.

A Dockerfile is included (container build is not part of the Go test suite):

```sh
docker build -t juardrails .
# Set an initial JUARDRAILS_ADMIN_PASSWORD in your shell, or retrieve the generated /data/bootstrap-admin.json.
docker run --rm -p 127.0.0.1:8080:8080 \
  -e JUARDRAILS_ADMIN_PASSWORD -e TYPESAFE_API_KEY \
  -v juardrails-data:/data juardrails
```
