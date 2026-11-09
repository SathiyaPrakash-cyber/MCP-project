# MCP Gateway — Policy-Based Access Control

> ### ⚠️ Laboratory stack — not a production deployment
>
> This repository builds the single-host experimental environment used to
> produce the results in the dissertation. It is deliberately simplified and
> must not be exposed beyond the machine it runs on:
>
> * Elasticsearch runs with X-Pack security disabled (no authentication on the
>   audit index) and Kibana is unauthenticated.
> * OPA's API is unauthenticated. It is bound to loopback, but anyone with
>   shell access on the host can read and evaluate policy.
> * `mock-mcp-server` is a test double that exposes `/admin/mutate_tool` and
>   `/admin/reset_tools` so the rug-pull experiment can change a tool at
>   runtime. These now require `MOCK_ADMIN_TOKEN`, but the service itself is
>   not hardened.
> * Transport between services is plain HTTP.
>
> Only the gateway's own port is published for general use; every
> administrative port is bound to `127.0.0.1`. No secret is committed: run
> `./scripts/bootstrap_env.sh` once to generate `.env`, and the stack refuses
> to start without it. `docker-compose.yml` names each simplification and
> states what a real deployment would require instead.

> **Credential rotation:** a previously distributed archive contained local
> JWT and mock-admin credentials. Treat those values as compromised. In an
> existing checkout, run `./scripts/bootstrap_env.sh --force`, then recreate
> the containers so both services load the new values. This source archive
> contains only `.env.example`; never add `.env` to a shared archive.

> MSc Advanced Computer Science Dissertation Artefact
> University of Roehampton · School of Computer Science and Engineering
> *Designing an MCP Gateway with Policy-Based Access Control*

This repository is the implementation behind the dissertation. The README is written
to be read alongside it: it explains how the components fit together, how to configure
and run the system, and exactly which script produces each result reported in
Chapter 4 (see [Reproduction guide](#6-reproduction-guide)).

---

## Contents

1. [What this is](#1-what-this-is)
2. [Architecture](#2-architecture)
3. [Component reference](#3-component-reference)
4. [Configuration](#4-configuration)
5. [Quick start](#5-quick-start)
6. [Reproduction guide](#6-reproduction-guide)
7. [Evaluation results](#7-evaluation-results)
8. [Policy model](#8-policy-model)
9. [Project structure](#9-project-structure)

---

## 1. What this is

The MCP Gateway is a security enforcement layer between LLM agents and Model Context
Protocol (MCP) tool servers. It intercepts every tool call, verifies the caller's
identity (JWT), asks Open Policy Agent for a hybrid RBAC + ABAC decision, checks that
the tool's schema has not changed since start-up (rug-pull detection), and then either
forwards the call upstream or blocks it. Every decision is written to a hash-chained,
append-only audit log that is also shipped to Elasticsearch for Kibana dashboards.

In XACML/NIST SP 800-162 terms:

| Role | Implemented by |
|---|---|
| Policy Enforcement Point (PEP) | `gateway/main.py` |
| Policy Decision Point (PDP) | OPA container, evaluating `policies/mcp_gateway.rego` |
| Policy Administration Point (PAP) | `gateway/admin_api.py` + `gateway/policy_versioning.py` |
| Policy Information Point (PIP) | JWT claims (`gateway/auth.py`) + request context (time, IP, session) |

---

## 2. Architecture

Five Docker containers on one bridge network (`mcp-net`):

```
                         ┌──────────────────────────── mcp-net (Docker bridge) ────────────────────────────┐
                         │                                                                                  │
 LLM agent / test script │   ┌──────────────────────┐   ② POST /v1/data/mcp_gateway/authz/decision         │
 ── HTTP + Bearer JWT ──────▶│  mcp-gateway  :8080  │─────────────────────────────▶ ┌──────────────┐     │
                         │   │  (FastAPI, the PEP)  │◀──────── {allow, reason, ──── │  opa  :8181  │     │
 ◀── 200 result / 403 ───────│                      │          rule_matched}        │  (the PDP)   │     │
                         │   │                      │                               └──────────────┘     │
                         │   │                      │   ③ POST /mcp  tools/list  (schema-pin check)       │
                         │   │                      │   ④ POST /mcp  tools/call  (only if allowed)        │
                         │   │                      │─────────────────────────────▶ ┌──────────────────┐ │
                         │   │                      │◀───────────────────────────── │ mock-mcp-server  │ │
                         │   │                      │                               │ :9000 (upstream) │ │
                         │   └──────────┬───────────┘                               └──────────────────┘ │
                         │              │ ⑤ audit record (authorization before ④; completion after)                        │
                         │              ├──────────────▶ logs/mcp_audit_YYYY-MM-DD.ndjson (host volume)    │
                         │              └──────────────▶ ┌─────────────────────┐    ┌──────────────┐      │
                         │                  _bulk API    │ elasticsearch :9200 │◀───│ kibana :5601 │      │
                         │                               └─────────────────────┘    └──────────────┘      │
                         └──────────────────────────────────────────────────────────────────────────────────┘
```

| Container | Image / build | Role |
|---|---|---|
| `mcp-gateway` | `docker/Dockerfile.gateway` | Policy Enforcement Point. Only component clients talk to. |
| `opa` | `openpolicyagent/opa:0.68.0` | Policy Decision Point. Loads `policies/mcp_gateway.rego` at start; accepts hot-reloaded policies over its REST API. |
| `mock-mcp-server` | `docker/Dockerfile.mock` | Stand-in for real MCP tool servers (filesystem, database, code, SaaS, admin). Returns simulated results; exposes `/admin/mutate_tool` so a rug pull can be staged. |
| `elasticsearch` | `elasticsearch:8.13.0` | Stores audit records for search/aggregation (SIEM store). |
| `kibana` | `kibana:8.13.0` | Dashboards over the `mcp-gateway-audit` index. |

Start-up order is enforced by health checks: the gateway waits for OPA and the mock
server to be healthy; Kibana waits for Elasticsearch.

### Life of one request

Example: a `developer` calls `filesystem.read`.

1. **Authenticate** — `POST /mcp/v1/tools/call` with `Authorization: Bearer <JWT>`.
   `auth.verify_token` checks the HS256 signature and expiry and extracts
   `sub`, `role`, `groups`, `email`. Missing or invalid token → **401**, and an
   `auth_failure` record is still written to the audit log.
2. **Build policy input** — `main._build_policy_input` combines identity
   (`user.role`, `groups`), the tool (`tool.name`, `tool.args`) and context
   (`hour` in UTC, `source_ip`, `session_id`) into one OPA input document.
3. **Decide** — `policy_engine.evaluate` makes a single call to OPA's
   `mcp_gateway/authz/decision` rule, which returns `{allow, reason, rule_matched}`.
   Rego evaluates, in order: explicit denies (globally blocked tools, privileged
   tools, agent off-hours destructive tools) → RBAC role permissions → ABAC context
   (off-hours for `read_only`, sensitive tools need elevated role, blocked IPs) →
   argument inspection (SQL-injection / path-traversal patterns). Tool names are
   lower-cased and trimmed first, so `SYSTEM.Format_Disk` cannot bypass a rule.
   Decisions are cached for 1 s keyed on the *entire* input. If OPA is unreachable
   the engine **fails closed** (deny).
4. **Deny path** — if `allow` is false the gateway writes the audit record and
   returns **403** immediately. No upstream call is made; this short-circuit is why
   deny latency is ~29× lower than allow latency (Figure 4.5).
5. **Rug-pull check** — on allow, the gateway fetches the current tool list from
   upstream and compares the SHA-256 of `filesystem.read`'s schema with the hash
   pinned at start-up (`schema_pinning.py`). Mismatch → **403 `rug_pull_detected`**.
6. **Forward** — the request is routed by tool prefix (`UPSTREAM_FS` for
   `filesystem.*`, etc.) to the MCP server, with the caller's token.
7. **Audit** — the completed record (decision, reason, rule, policy/upstream/total
   latency, IP, session) is chained to the previous record's hash, appended to
   `logs/mcp_audit_<date>.ndjson`, kept in a 1,000-record memory buffer for
   `/audit/recent`, and posted to Elasticsearch.
8. **Respond** — **200** with the upstream result plus `gateway_meta`
   (`request_id`, `policy_latency_ms`, `total_latency_ms`).

### Policy change path

An admin uploads Rego through `POST /admin/policies`. `policy_versioning.py` validates
it by pushing to a temporary OPA policy id, stores it as a new version in
`policies/version_store.json` (with SHA-256, author, timestamp), and on
`/activate` pushes it to OPA with `PUT /v1/policies/mcp_gateway`. The next request is
evaluated against the new policy with no restart. `/admin/policies/rollback`
re-activates the previous version.

### HTTP endpoints (gateway, port 8080)

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /mcp` | any valid role | **MCP endpoint, revision 2026-07-28** (JSON-RPC 2.0 over the Streamable HTTP transport). Methods: `server/discover`, `tools/list`, `tools/call`; `ping` is not implemented. Every request must carry the per-request protocol metadata (`params._meta` with `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`) and the `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` HTTP headers; the `Origin` header is validated. Notifications return HTTP 202, batches are rejected (400), unknown methods and legacy `initialize` return 404/`-32601`. Policy and schema denials are JSON-RPC errors with application codes outside the reserved range (`-1000` policy, `-1001` schema, `-1002` upstream, `-1003` audit unavailable). |
| `POST /mcp/v1/tools/call` | any valid role | Native REST tool call, used by the evaluation harness. Same enforcement path as `/mcp` — `_execute_tool_call` in `main.py` — so the two interfaces cannot disagree. |
| `POST /mcp/v1/tools/list` | any valid role | Lists only the tools the caller's policy allows |
| `GET /health` | none | Gateway + OPA reachability |
| `GET /metrics` | admin, security_analyst | Allow/deny/error counters |
| `GET /audit/recent?limit=N` | admin, security_analyst | Last N audit records |
| `GET/POST /admin/policies…`, `GET /admin/status` | admin | Policy versioning, activation, rollback, diff |
| `GET /dashboard` | token entered in page | Admin dashboard UI |
| `GET /docs` | none | OpenAPI / Swagger UI |

---

## 3. Component reference

### `gateway/`

| File | What it does |
|---|---|
| `main.py` | FastAPI app and Policy Enforcement Point. Start-up wiring (JWT secret check, OPA client, audit logger, policy manager, per-upstream schema pinning with retry and seal); the shared `_execute_tool_call` enforcement pipeline behind both `/mcp` (MCP 2026-07-28) and `/mcp/v1/tools/call` (custom REST adapter, not MCP); audit-before-execution ordering (durable `authorization` record written before the upstream call, `completion` record after); `_schema_guard` fail-closed per-upstream verification; role-filtered tool listing; `/health`, `/metrics`, `/audit/recent`, `/dashboard`; prefix-based upstream routing over MCP; audit record on 401. |
| `mcp_protocol.py` | MCP revision 2026-07-28 constants and validation: required `params._meta` fields, `MCP-Protocol-Version`/`Mcp-Method`/`Mcp-Name` header checks (with the Base64 sentinel decoder for unsafe header values), `Origin` and `Accept` validation, JSON and SSE upstream response parsing, and cursor-based retrieval of every upstream `tools/list` page. |
| `jsonrpc.py` | JSON-RPC 2.0 envelope layer: request validation (null ids forbidden, per MCP 2026-07-28), notifications, the reserved error codes (`-32700`…`-32603`), the MCP protocol errors (`-32020` header mismatch, `-32021` missing client capability, `-32022` unsupported version), and the application codes (`-1000`…`-1003`) used to carry policy, schema, upstream and audit denials to an MCP client — allocated outside the JSON-RPC reserved range as the specification directs. JSON-RPC batching is not implemented: the Streamable HTTP transport carries one message per POST. |
| `auth.py` | JWT verification (HS256) into `TokenClaims`; refuses to start if `JWT_SECRET` is under 32 chars, and refuses any value published in this repository unless `MCP_GATEWAY_LAB_MODE=1` is set; defines valid roles; `generate_test_token()` used by all test scripts. |
| `policy_engine.py` | OPA client (PDP interface). One HTTP call per decision to `mcp_gateway/authz/decision`; 1 s decision cache keyed on the full input; fails closed on any OPA error; logs a warning when evaluation exceeds 50 ms. |
| `audit_logger.py` | Append-only NDJSON audit trail, one file per UTC day. Each record carries `prev_hash`/`record_hash` (SHA-256 chain, resumed across restarts) and an event type. File writes are flushed and `fsync` is required to succeed before the in-memory chain head advances; a write or sync error makes the logger fail closed for later writes. An authorization record is attempted before the upstream call. If the tool ran but its completion record fails, the gateway returns HTTP 503 and explicitly reports that execution may have succeeded without a completion record. This is an application-level file and OS sync guarantee; it does not promise physical-media survival or identical guarantees on every network filesystem. Elasticsearch shipping is best effort and is not part of the durable local audit path. |
| `schema_pinning.py` | Rug-pull detection, per upstream. Pins the SHA-256 of every tool definition returned by all cursor pages of each upstream's MCP `tools/list` at start-up, then **seals that upstream's** registry so trust-on-first-use cannot apply on the request path. After sealing, an unpinned tool, a tool withdrawn upstream, a failed schema lookup and a changed definition all deny the call; an upstream whose baseline could not be built stays unsealed and denies everything routed to it. Reports drift and unpinned-denial counts. |
| `policy_versioning.py` | Policy Administration Point logic: create / validate / activate / roll back / diff Rego versions; persists to `policies/version_store.json`; hot-loads into OPA via its REST API. |
| `admin_api.py` | `/admin/*` REST router (admin role only) exposing `policy_versioning.py` and a combined gateway/OPA status call. |
| `models.py` | Dataclasses: `MCPRequest`, `MCPResponse`, `AuditRecord` (and its SIEM dict form), `GatewayConfig` (reads the environment variables in §4). |
| `mock_server.py` | Mock upstream **MCP 2026-07-28 server** (runs in its own container): 15 tools with valid JSON Schema 2020-12 `inputSchema`, `server/discover`/`tools/list`/`tools/call` over JSON-RPC on `POST /mcp`; `tools/list` returns a multi-page cursor response. The server applies per-request `_meta` and header validation and returns correctly shaped `CallToolResult` responses. Also exposes `/admin/mutate_tool` / `/admin/reset_tools` for rug-pull experiments — these are NOT part of MCP, require an `X-Admin-Token` header matching `MOCK_ADMIN_TOKEN`, and are disabled outright if that variable is unset. |
| `dashboard.html` | Single-page admin dashboard served at `/dashboard`: health, counters, recent decisions, policy versions, activate/rollback buttons. |
| `__init__.py` | Package marker. |

### `policies/`

| File | What it does |
|---|---|
| `mcp_gateway.rego` | The hybrid RBAC + ABAC policy loaded by OPA (package `mcp_gateway.authz`). |
| `policy_rbac_only.rego` | RBAC-only variant, used only by the RQ2 comparison. |
| `policy_abac_only.rego` | ABAC-only variant, used only by the RQ2 comparison. |
| `version_store.json` | Policy version history; seeded with `v1-seeded` (the hybrid policy). |

### `tests/` and `scripts/`

Each is listed against the result it produces in the [Reproduction guide](#6-reproduction-guide).

---

## 4. Configuration

All configuration is by environment variable, set in `docker-compose.yml`.

### `mcp-gateway`

| Variable | Value in compose | Read by | Meaning |
|---|---|---|---|
| `OPA_URL` | `http://opa:8181` | `models.GatewayConfig` → `policy_engine`, `policy_versioning` | Base URL of the OPA decision/policy API. |
| `UPSTREAM_DEFAULT` | `http://mock-mcp-server:9000` | `models.GatewayConfig` | MCP server used for tools whose prefix matches no route below, and for tool listing / schema pinning. |
| `UPSTREAM_FS` | `http://mock-mcp-server:9000` | `models.GatewayConfig` | Upstream for `filesystem.*` tools. |
| `UPSTREAM_DB` | `http://mock-mcp-server:9000` | `models.GatewayConfig` | Upstream for `database.*` tools. |
| `UPSTREAM_CODE` | `http://mock-mcp-server:9000` | `models.GatewayConfig` | Upstream for `code.*` tools. |
| `UPSTREAM_SAAS` | `http://mock-mcp-server:9000` | `models.GatewayConfig` | Upstream for `saas.*` tools. |
| `JWT_SECRET` | from `.env` (generated) | `auth.py` | HMAC key for signing/verifying tokens. Generated by `./scripts/bootstrap_env.sh`; no value is committed. Must be ≥ 32 chars, and must not be any value published in this repository unless `MCP_GATEWAY_LAB_MODE=1`. Test scripts on the host must export the same value (`set -a; . ./.env; set +a`). |
| `MCP_GATEWAY_LAB_MODE` | `1` | `auth.py` | Acknowledges the laboratory stack. With `0`, the gateway refuses to start on a publicly known secret instead of logging a warning. |
| `SCHEMA_PIN_REQUIRED` | `1` | `main.py` | `1` makes the gateway refuse to start if it cannot seal a tool-schema baseline after five attempts. With `0` it starts but denies every tool call until a baseline is sealed. |
| `CORS_ALLOW_ORIGINS` | `http://localhost:8080` | `main.py` | Comma-separated browser origins allowed to call the gateway. Replaces the previous wildcard, which would have let any page replay a bearer token. |
| `JWT_ALGORITHM` | `HS256` | `auth.py` | JWT signature algorithm. |
| `LOG_DIR` | `/app/logs` | `models.GatewayConfig` → `audit_logger` | Where audit NDJSON is written. Mounted to `./logs` on the host, which is where the analysis scripts read it. |
| `ES_URL` | `http://elasticsearch:9200` | `audit_logger.py` | Elasticsearch endpoint for live audit shipping. Empty = shipping disabled (file log still written). |
| `ES_INDEX` | `mcp-gateway-audit` | `audit_logger.py` | Elasticsearch index name for audit records. |
| `DISABLE_POLICY_CACHE` | `0` | `policy_engine.py` | `1` disables the 1 s decision cache. The benchmark instead defeats the cache with a unique `session_id` per request, so it can stay `0`. |

Volumes: `./logs → /app/logs` (audit logs persist on the host) and
`./policies → /app/policies` (policy version store).

### Other services

| Service | Variable / setting | Meaning |
|---|---|---|
| `opa` | `command: run --server --addr=0.0.0.0:8181 … /policies/mcp_gateway.rego` | Runs OPA as a REST server, loading the hybrid policy from the read-only `./policies` mount. |
| `elasticsearch` | `discovery.type=single-node` | Single-node cluster (no peer discovery). |
| `elasticsearch` | `xpack.security.enabled=false` | Disables ES auth/TLS so the gateway can post without credentials. **Lab use only** — see the banner at the top of this file. |
| `mock-mcp-server` | `MOCK_ADMIN_TOKEN` (from `.env`) | Guards `/admin/mutate_tool` and `/admin/reset_tools`. Unset means those routes return 503 rather than being open. |
| all | port bindings | Only the gateway publishes on `${GATEWAY_BIND:-127.0.0.1}:8080`. OPA (8181), the mock server (9000), Elasticsearch (9200) and Kibana (5601) are bound to `127.0.0.1`. |
| `elasticsearch` | `ES_JAVA_OPTS=-Xms256m -Xmx256m` | Caps the JVM heap at 256 MB so the stack runs on a laptop. |
| `kibana` | `ELASTICSEARCH_HOSTS=["http://elasticsearch:9200"]` | Which Elasticsearch Kibana reads from. |

### Constants in the test scripts

| Script | Constant | Value |
|---|---|---|
| `tests/benchmark.py` | `CONCURRENCY_LEVELS`, `SAMPLES_PER_CELL`, `REPEATS`, `SEED`, `SLA_MS` | `[1,5,10,25,50,100]`, `1000`, `3`, `1337`, `50.0` |
| `tests/anomaly_detector.py` | `WINDOW_SECONDS`, `DENY_THRESHOLD` | `60`, `5` |
| `tests/attack_simulation.py` | `MOCK_URL` (env, optional) | `http://localhost:9000` |

---

## 5. Quick start

Requirements: Docker (with Compose) and Python 3.11+ on the host for the test scripts.

```bash
cd mcp-gateway
./scripts/bootstrap_env.sh             # generates .env with random secrets (once)
docker compose up -d --build
sleep 30                               # wait for health checks
curl http://localhost:8080/health      # {"status":"ok","opa":"reachable",...}
```

`bootstrap_env.sh` writes a `.env` containing a fresh `JWT_SECRET` and
`MOCK_ADMIN_TOKEN`. Compose will refuse to start without it — this is
deliberate, so that no credential ever lives in the repository.

| Service | URL |
|---|---|
| MCP Gateway | http://localhost:8080 |
| Admin dashboard | http://localhost:8080/dashboard |
| API docs | http://localhost:8080/docs |
| MCP endpoint (JSON-RPC 2.0) | http://localhost:8080/mcp |
| OPA | http://127.0.0.1:8181 (loopback only) |
| Mock MCP server | http://127.0.0.1:9000 (loopback only) |
| Elasticsearch | http://127.0.0.1:9200 (loopback only) |
| Kibana | http://127.0.0.1:5601 (loopback only) |

Host-side Python environment for the tests and analysis:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt matplotlib
set -a; . ./.env; set +a    # exports JWT_SECRET and MOCK_ADMIN_TOKEN for the test scripts
```

The test scripts read both from the environment and have no committed
fallback, so forgetting this step produces an authentication failure rather
than silently signing with a known key.

Admin token for the dashboard (paste into the token bar, click Refresh):

```bash
python scripts/gen_token.py --role admin --user admin
```

Stop: `docker compose down` (add `-v` to also delete the Elasticsearch volume).

---

## 6. Reproduction guide

Run every command from the `mcp-gateway/` directory with the stack up and the
environment from §5 active. Each script writes a timestamped file to `logs/`;
the file names below are the ones cited in the dissertation and are already
included in `logs/`.

### Step 0 — offline test suites (no Docker, no OPA, no network)

These drive the application through its ASGI interface with the policy engine
and upstream replaced by local doubles, so they run from a clean extraction
with only the Python dependencies installed. The current run recorded in
`verification/offline-pytest.txt` passed all 50 tests.

`pytest tests/` intentionally leaves out `tests/test_gateway.py`: that file is a
Docker-backed integration harness, not a pytest module. Run it separately with
`python tests/test_gateway.py` after starting the stack (see Step 1).

| # | Command | Verifies |
|---|---|---|
| 0a | `pytest -q tests/test_mcp_protocol.py` | MCP 2026-07-28 conformance including removal of `ping`, metadata validation, error handling, and enforcement parity — 27 tests |
| 0b | `pytest -q tests/test_schema_pinning.py` | Fail-closed, per-upstream schema pinning: unpinned tool, tool withdrawn upstream, upstream outage, unsealed registry, missing pinner, independence of two upstreams, and the one legitimate call that must still succeed — 11 tests |
| 0c | `pytest -q tests/test_audit_ordering.py` | Audit-before-execution, failed completion reporting, failed authorization handling, and fsync failure fail-closed behavior — 7 tests |
| 0d | `pytest -q tests/test_audit_chain_concurrency.py` | Hash-chain continuity under 50 concurrent writers, plus a guard test asserting the pre-fix implementation is detectably broken — 2 tests |
| 0e | `pytest -q tests/test_mcp_upstream_transport.py` | SSE upstream response parsing, multi-page `tools/list` retrieval, and repeated-cursor rejection — 3 tests |
| 0f | `python tests/audit_chain_experiment.py` | Table 4.10: chain integrity before and after the locking fix, across concurrency levels → `results/audit_chain_integrity.csv` |
| 0g | `python scripts/verify_chain.py logs/` | Chain-integrity report over the shipped audit logs. Exits non-zero, by design: the logs in `logs/` were written by the pre-fix logger and are reported as broken rather than regenerated. |

Run all four offline suites at once:

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q tests/test_mcp_protocol.py tests/test_schema_pinning.py \
        tests/test_audit_ordering.py tests/test_audit_chain_concurrency.py \
        tests/test_mcp_upstream_transport.py
```

This offline command was run for this package: **50 passed**. Its recorded
output is in `verification/offline-pytest.txt`.

### Official MCP SDK interoperability check

The gateway was also exercised over loopback using the official MCP Python SDK
client (`mcp==2.3.0`). The check starts the real FastAPI gateway and substitutes
local doubles only for OPA and the upstream server. It covers discovery, the
policy-filtered tool list, an allowed tool call, and a denied tool call. Install
the optional client dependency and run the check with:

```bash
pip install -r requirements-official-client.txt
pip install --no-deps mcp==2.3.0 sse-starlette==3.5.0
python tests/official_mcp_client_smoke.py
```

The captured result is in `verification/official-mcp-client.txt`. This verifies
client/server wire interoperability for those operations; it is not a full
end-to-end run against Docker, OPA, or a production upstream.

The uploaded source archive supplied three successful 13/13 Docker test logs.
They are retained under `verification/prior-revision-docker-output/` with a
provenance note, but they are historical: they were produced by an earlier
revision and are not evidence for this repaired source. A fresh run of this
revision's integration suite, taken against the rebuilt Docker stack, is
recorded in `verification/test_gateway_20261016_162132.txt` (13/13 passed,
process exit code 0).

### Step 1 — experiments that need the running stack

| # | Command | Produces (report) | Output file(s) | Report file |
|---|---|---|---|---|
| 1 | `python tests/test_gateway.py` | 13-test integration suite; each report row maps to a named function in this file. Requires the running Docker stack. Fresh output for this repaired source is in `verification/test_gateway_20261016_162132.txt` (13/13 passed); the earlier logs remain under `verification/prior-revision-docker-output/` as historical, pre-repair evidence. | console | `verification/test_gateway_20261016_162132.txt` |
| 2 | `python tests/attack_simulation.py` | Attack simulation table — 81/81 blocked, per attack class | `logs/attack_results_<ts>.csv` | `attack_results_20260604_094431.csv` |
| 3 | `python tests/test_rug_pull.py` | Live rug-pull (schema drift) demonstration — 200 before mutation, 403 `RUG_PULL_DETECTED` after | console | — |
| 4 | `python tests/benchmark.py` | **RQ1** latency table and **Figure 4.1** (E2E + policy-evaluation latency vs concurrency, SLA pass %) | `logs/benchmark_deterministic_<ts>.csv` | `benchmark_deterministic_20260609_170742.csv` |
| 5 | `python tests/policy_comparison.py` | **RQ2** RBAC vs ABAC vs Hybrid table and **Figure 4.2** (7/9, 7/9, 9/9) | `logs/rq2_policy_comparison_<ts>.csv` | `rq2_policy_comparison_20260609_165854.csv` |
| 6 | `python tests/baseline_no_gateway.py` | **RQ3** measured attack-success rate and **Figure 4.3** (13/13 unmediated → 0/13 via gateway) | `logs/baseline_both_sides_<ts>.csv` | `baseline_both_sides_20260609_170046.csv` |
| 7 | `python scripts/ingest_to_es.py` | Back-fills all audit logs into Elasticsearch so the dashboard has data | ES index `mcp-gateway-audit` | — |
| 7b | open http://localhost:8080/dashboard and paste an admin token | **Figure 4.7** gateway admin dashboard (health, counters, recent decisions, policy versions) | screenshot | — |
| 7c | open http://127.0.0.1:5601 → Discover → index `mcp-gateway-audit` | Kibana view of the indexed audit stream referenced in §4.8 | screenshot | — |

Notes:
- `policy_comparison.py` talks to OPA directly: it swaps in each policy, evaluates
  the 9 cases, then restores the hybrid policy.
- `baseline_no_gateway.py` sends each of the 14 corpus requests twice — straight to
  the mock server and through the gateway. Thirteen are adversarial probes and one is
  a legitimate true-negative control. The expected result is **0/13 adversarial
  probes succeeding through the gateway**, with the control correctly allowed. The
  control is reported separately: counting a legitimate allowed request as an attack
  success would give a misleading 1/14.
- `benchmark.py` aborts if any request errors, so a completed run has 0 errors in
  every cell.

### Step 2 — offline analysis of the audit log (no stack needed)

These read `logs/mcp_audit_*.ndjson`, which step 1 generates. Run them after step 1.

| # | Command | Produces (report) | Output file(s) | Report file |
|---|---|---|---|---|
| 8 | `python tests/policy_mining.py` | Mined least-privilege policy and **Figure 4.4** (over-permission % per role) | `logs/mined_policy_<ts>.rego`, `logs/policy_mining_report_<ts>.json`, `logs/over_permission_score_<ts>.json` | `over_permission_score_20261015_065135.json` |
| 9 | `python tests/latency_analysis.py` | **Figure 4.5** allow-path vs deny-path latency (92.86 ms vs 3.20 ms, 29×) | `logs/latency_analysis_<ts>.json` | `latency_analysis_20260610_153626.json` |
| 10 | `python tests/anomaly_detector.py` | **Figure 4.6** deny-burst alerts per user, by severity | `logs/anomaly_alerts_<ts>.csv` | `anomaly_alerts_20260610_153709.csv` |

### Step 3 — figures

| # | Command | Produces |
|---|---|---|
| 11 | `python tests/generate_figures.py` | `figures/fig4_1_…png`, `fig4_2_…`, `fig4_3_…`, `fig4_4_…`, `fig4_5_…`, `fig4_6_…` from the report files above |
| 11b | `python tests/generate_figures.py --latest` | Same figures from the newest file of each kind (use after re-running steps 1–2) |

| Figure | File | Source data |
|---|---|---|
| Figure 4.1 | `figures/fig4_1_latency_vs_concurrency.png` | `benchmark_deterministic_20260609_170742.csv` |
| Figure 4.2 | `figures/fig4_2_policy_comparison.png` | `rq2_policy_comparison_20260609_165854.csv` |
| Figure 4.3 | `figures/fig4_3_attack_success_baseline.png` | `baseline_both_sides_20260609_170046.csv` |
| Figure 4.4 | `figures/fig4_4_over_permission.png` | `over_permission_score_20261015_065135.json` |
| Figure 4.5 | `figures/fig4_5_allow_vs_deny_latency.png` | `latency_analysis_20260610_153626.json` |
| Figure 4.6 | `figures/fig4_6_anomaly_alerts.png` | `anomaly_alerts_20260610_153709.csv` |

Re-run numbers will differ slightly from the report (latency depends on the host
machine; mining/latency/anomaly results depend on how much traffic is in the audit
log), but the decisions in RQ2/RQ3 and the attack simulation are deterministic.

---

## 7. Evaluation results

### Tests

The offline command and the integration command are listed below. Counts are
maintained from the most recent recorded run; do not treat historical counts
as verification of a later code revision. Offline tests use hand-authored
protocol fixtures. The optional official-client smoke check is separately
recorded in `verification/official-mcp-client.txt`; the integration suite was
rerun for this revision against the Docker stack and is recorded in
`verification/test_gateway_20261016_162132.txt` (13/13 passed), while the older
Docker logs under `verification/prior-revision-docker-output/` are explicitly
marked as pre-repair evidence.

| Suite | Tests | Needs the stack? |
|---|---|---|
| `tests/test_gateway.py` (Table 4.8) | 13 | yes |
| `tests/test_mcp_protocol.py` (Table 4.9) | 27 | no |
| `tests/test_schema_pinning.py` (Table 4.9) | 11 | no |
| `tests/test_audit_ordering.py` | 7 | no |
| `tests/test_audit_chain_concurrency.py` (Table 4.9) | 2 | no |
| `tests/test_mcp_upstream_transport.py` | 3 | no |

### Attack simulation: 81/81 blocked (100 % detection)

| Attack class | Attempts | Detected | Rate |
|---|---|---|---|
| Privilege escalation | 19 | 19 | 100 % |
| Tool poisoning | 19 | 19 | 100 % |
| Rug pull / confused deputy | 19 | 19 | 100 % |
| Auth bypass | 5 | 5 | 100 % |
| ABAC context bypass | 19 | 19 | 100 % |
| **Total** | **81** | **81** | **100 %** |

### RQ1 — latency (deterministic: seed 1337, 1,000 samples/cell, 3 repeats)

Source: `logs/benchmark_deterministic_20260609_170742.csv` · Figure 4.1

| Concurrency | E2E mean | E2E 95 % CI | Policy mean | Requests < 50 ms |
|---|---|---|---|---|
| 1 | 28.30 ms | ±1.05 ms | 3.19 ms | 97.0 % |
| 5 | 70.20 ms | ±1.50 ms | 10.86 ms | 11.6 % |
| 10 | 120.68 ms | ±1.10 ms | 19.16 ms | 0.1 % |
| 25 | 300.45 ms | ±3.29 ms | 54.72 ms | 0.0 % |
| 50 | 622.92 ms | ±7.08 ms | 106.41 ms | 0.0 % |
| 100 | 1192.43 ms | ±15.73 ms | 78.11 ms | 0.0 % |

The 50 ms SLA holds at concurrency 1 (97 % of requests). The policy-evaluation step
(measured inside the gateway and reported in `gateway_meta.policy_latency_ms`) is a
small share of end-to-end latency at every level; the growth under load comes from
request queuing in the single-worker gateway and the per-call schema-pinning round-trip
to the upstream server. (In the shipped CSV the column is named `opa_mean_ms`; it
carries the policy-evaluation step, not a direct OPA-only measurement.)

### RQ2 — policy model comparison (9 cases) · Figure 4.2

| Model | Correct decisions |
|---|---|
| RBAC-only | 7/9 |
| ABAC-only | 7/9 |
| Hybrid PBAC | 9/9 |

### RQ3 — attack success rate (13 adversarial probes + 1 control) · Figure 4.3

| Measure | Value |
|---|---|
| Adversarial probes | 13 (plus 1 legitimate true-negative control) |
| Unmediated adversarial success | 13 / 13 = 100 % |
| **Gateway adversarial success** | **0 / 13 = 0 %** |
| Legitimate control | 1 / 1 correctly allowed (no false positive) |

The control is counted separately. A legitimate request that is correctly allowed is
not an attack success, so reporting "1/14 = 7.1 %" conflates two different
measurements. This is a small, locally constructed probe set chosen to represent
documented MCP attack classes — a demonstration that these classes are blocked, not
a general security guarantee.

### Extensions

| Analysis | Result | Figure |
|---|---|---|
| Allow vs deny latency | 92.86 ms vs 3.20 ms — deny 29× faster (no upstream call) | Figure 4.5 |
| Policy mining over-permission | 75 %–87 % for the three roles with observed activity (wildcards expanded against the 23-tool universe); `security_analyst` and `agent` show 100 % only because neither generated an allowed call | Figure 4.4 |
| Deny-burst anomaly detection | 3 alerts (1 HIGH, 2 MEDIUM) | Figure 4.6 |
| Audit hash-chain integrity | pre-fix: unbroken only at 1 writer, every link broken from 2 upwards; post-fix: unbroken at 1–100 concurrent writers | Table 4.10 |

### Known limitation of the shipped audit logs

The NDJSON files in `logs/` were written by the pre-fix audit logger, which
computed each record hash before taking the writer lock. `scripts/verify_chain.py`
reports 15,879 of 22,282 links broken in the 6 June file and 13,311 of 18,015 in
the 9 June file, with 5,503 earlier records carrying no hash at all. They are
shipped unaltered: a chain recomputed after the fact would evidence nothing. The
corrected logger is verified by `tests/test_audit_chain_concurrency.py` and
`tests/audit_chain_experiment.py`.

The shipped logs predate the audit-before-execution ordering, so their records
carry no `event_type` field (readers must treat a missing `event_type` as the
legacy `decision` record). New records written by the current gateway are tagged
`authorization`, `completion` or `denial`; `tests/latency_analysis.py` filters on
this field so the pre-execution `authorization` record is not counted alongside
its `completion` record.

---

## 8. Policy model

Role permissions in `policies/mcp_gateway.rego` (`*` = any tool with that prefix):

| Role | Permitted tools |
|---|---|
| `admin` | `filesystem.*`, `database.*`, `code.*`, `saas.*`, `system.*`, `admin.*` |
| `security_analyst` | `filesystem.read/list`, `database.read/query`, `saas.read`, `audit.*`, `logs.*` |
| `developer` | `filesystem.read/write/list`, `code.*`, `database.read/query`, `saas.read/webhook` |
| `read_only` | `filesystem.read/list`, `database.read`, `saas.read` |
| `agent` | `filesystem.read/list`, `database.read/query`, `code.execute`, `saas.read` |

Rules layered on top of RBAC:

| Rule | Effect |
|---|---|
| Globally blocked (`system.format_disk`, `admin.drop_all_tables`, `system.rm_rf_root`) | Denied for every role, including admin |
| Privileged (`code.execute_privileged`, `system.exec`, `system.sudo`) | Admin only |
| Sensitive (e.g. `database.drop`, `admin.create_user`, `code.deploy_production`) | Requires `admin` or `security_analyst` |
| Off-hours (before 06:00 or from 22:00 UTC) | `read_only` denied everything; `agent` denied destructive tools |
| Argument inspection | Deny SQL-injection patterns (`' or `, `drop table`, `union select`, `; delete from`) and `../` path traversal |
| Name canonicalisation | Tool names lower-cased and trimmed before every check |

---

## 9. Project structure

```
mcp-gateway/
├── gateway/                 # the gateway service — see §3
├── policies/                # Rego policies + version store
├── tests/
│   ├── test_gateway.py      # 13 integration tests (Table 4.8, needs the stack)
│   ├── test_mcp_protocol.py # 27 MCP 2026-07-28 conformance tests (offline)
│   ├── test_schema_pinning.py # 11 fail-closed per-upstream pinning tests (offline)
│   ├── test_audit_ordering.py # 7 audit and fsync failure tests (offline)
│   ├── test_audit_chain_concurrency.py # 2 hash-chain concurrency tests (offline)
│   ├── test_mcp_upstream_transport.py # 3 SSE and pagination tests (offline)
│   ├── official_mcp_client_smoke.py # official SDK interoperability smoke test
│   ├── audit_chain_experiment.py # Table 4.10 pre/post-fix chain integrity
│   ├── attack_simulation.py # 81 adversarial cases
│   ├── test_rug_pull.py     # live schema-drift test
│   ├── benchmark.py         # RQ1 latency benchmark
│   ├── policy_comparison.py # RQ2 RBAC vs ABAC vs Hybrid
│   ├── baseline_no_gateway.py # RQ3 unmediated vs gateway
│   ├── policy_mining.py     # mined policy + over-permission score
│   ├── latency_analysis.py  # allow vs deny latency
│   ├── anomaly_detector.py  # deny-burst detection
│   └── generate_figures.py  # Chapter 4 figures from logs/
├── scripts/
│   ├── bootstrap_env.sh     # generate .env with random JWT and admin secrets
│   ├── verify_chain.py      # audit hash-chain integrity verifier
│   ├── gen_token.py         # issue a test JWT for any role
│   └── ingest_to_es.py      # back-fill audit logs into Elasticsearch
├── docker/                  # Dockerfiles for gateway and mock server
├── logs/                    # experiment outputs and audit logs cited in the report
├── results/                 # chain-integrity experiment output
├── figures/                 # generated PNG figures
├── docker-compose.yml
├── .env.example             # template; run scripts/bootstrap_env.sh to generate .env
├── requirements.txt         # runtime dependencies (used by the Docker image)
├── requirements-dev.txt     # offline test dependencies
├── requirements-official-client.txt # optional official MCP SDK test client
└── verification/            # captured offline, SDK, and historical Docker output
└── README.md
```

---

## Tech stack

Python 3.11 · FastAPI · Open Policy Agent 0.68.0 · Rego · JWT (HS256) · Docker Compose ·
Elasticsearch 8.13 · Kibana 8.13 · matplotlib

## References

- Narajala & Habler (2025) — arXiv:2504.08623
- Bhatt et al. (2025) — arXiv:2506.01333
- OWASP Top 10 for LLM Applications (2025)
- NIST SP 800-162, *Guide to Attribute Based Access Control*
