# Sandbox DB Plan

> Live plan + progress tracker for `sqldb-sandbox-setup`.
> Owner: taosam · Started: 2026-06-29

---

## 1. Goal

A Python API server that, **per support ticket**, provisions an isolated `mysql:8` container pre-loaded with anonymized DBs pulled from production, hands the developer a per-DB scoped MySQL user on a public TLS-protected random port, and **auto-nukes** the container at TTL while keeping an audit-friendly log bind-mount on the host.

### Non-goals
- Not a multi-engine stack — MySQL only.
- Not a long-lived dev environment — short-lived (4–8h) by design.
- Not a replacement for prod data masking — masking is done **in prod** (salted columns). The sandbox only pulls what's already safe.

---

## 2. Architecture (one-paragraph)

A FastAPI service (`api/`) listens on a public host. When the ticket system POSTs to `/instance`, the API opens an SSH tunnel to prod, dumps the requested DBs with a dump-only MySQL user, closes the tunnel, then writes a per-session `docker-compose.yml`, brings up a hardened `mysql:8` container with self-signed TLS, restores the dumps, creates one scoped MySQL user per DB, publishes the container's `3306` on a random public port, persists the encrypted credentials in SQLite, and returns connection details to the caller. A background reaper nukes expired sessions. An IP/CIDR/hostname allowlist plus an `X-API-Key` header gate every endpoint.

---

## 3. Repo layout

```
sqldb-sandbox-setup/
├── PLAN.md                  ← this file
├── README.md
├── requirements.txt
├── .env.example
├── api/
│   ├── __init__.py
│   ├── main.py              FastAPI app, routes
│   ├── config.py            pydantic-settings; reads .env
│   ├── models.py            Pydantic request/response
│   ├── state.py             SQLite session store (encrypted creds)
│   ├── auth.py              API key + IP allowlist dependency
│   ├── crypto.py            Fernet + password gen + constant-time compare
│   ├── ssh_tunnel.py        Paramiko tunnel to prod
│   ├── mysql_ops.py         mysqldump + restore + per-DB grants
│   ├── docker_ops.py        compose file render, port alloc, up/down
│   ├── tls_ops.py           per-session CA + leaf cert
│   └── reaper.py            background TTL sweeper
├── templates/
│   ├── docker-compose.yml.j2
│   ├── mysqld.cnf.j2
│   └── grant_user.sql.j2
├── scripts/
│   ├── bootstrap.sh         one-time host prep
│   ├── run.sh               uvicorn launcher
│   └── smoke.sh             curl-based smoke test
└── tests/
    ├── test_state.py
    ├── test_auth.py
    ├── test_allowlist.py
    ├── test_endpoints.py
    ├── test_reaper.py
    ├── test_tls_ops.py
    └── test_mysql_ops.py
```

---

## 4. Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/instance` | Access JWT + API key (+ optional HMAC) | Create session |
| `GET` | `/session/{session_id}` | Access JWT + API key | Re-fetch creds |
| `POST` | `/session/{session_id}/reset-ttl` | Access JWT + API key | One-shot TTL extension |
| `DELETE` | `/session/{session_id}` | Access JWT + API key | Manual nuke (keeps logs) |
| `GET` | `/session-tls/{session_id}/ca.pem` | Access JWT + API key | CA cert for TLS client |
| `POST` | `/webhook/ticket-closed` | Webhook HMAC only | Ticket-system calls this on ticket close; idempotent nuke |
| `GET` | `/healthz` | none | Liveness |

### `POST /instance` contract

**Request**
```json
{ "ticket": "10215", "dbs": ["db_a", "db_b"] }
```

**Response 201**
```json
{
  "session_id": "f1c8...",
  "api_host": "api-testdb.abc.co.zm",
  "mysql_host": "198.51.100.10",
  "mysql_port": 33451,
  "expires_at": "2026-06-29T18:42:00Z",
  "max_extended_until": "2026-06-29T20:42:00Z",
  "ca_url": "https://api-testdb.abc.co.zm/session-tls/f1c8.../ca.pem",
  "databases": [
    { "name": "db_a", "user": "u_db_a_3kf2", "password": "..." },
    { "name": "db_b", "user": "u_db_b_8zx1", "password": "..." }
  ]
}
```

Note: `mysql_host` is the **host's public IP** (returned directly — no Cloudflare in front of MySQL per owner decision). `api_host` is the API domain. `ca_url` is HTTPS on the API domain.

### `POST /webhook/ticket-closed` contract

Body HMAC-signed with `SANDBOX_WEBHOOK_SECRET`, header `X-Sandbox-Signature: sha256=<hex>`. **No CF Access JWT, no API key required** — the ticket system may not have those.

**Request**
```json
{ "ticket": "10215", "session_id": "f1c8..." }
```

**Response 200**
```json
{ "ticket": "10215", "session_id": "f1c8...", "status": "nuked" }
```

`status` is `"nuked"` on first call, `"already_nuked"` on subsequent calls (idempotent). 404 if the session does not exist or `session_id` does not belong to the given ticket. 401 on missing/bad signature.

---

## 5. Per-session lifecycle

1. `POST /instance {ticket, dbs}` →
   1. Allocate free host port in `SANDBOX_PORT_RANGE` (default 33060–33999).
   2. Generate `session_id` (uuid4), `expires_at = now + 6h`, `max_extended_until = now + 8h`, `ttl_extended = 0`.
   3. Generate per-DB 24-char passwords and 32-char `MYSQL_ROOT_PASSWORD`.
   4. Generate TLS material (`ca.pem`, `server-cert.pem`, `server-key.pem`, `client-cert.pem`, `client-key.pem`) under `/var/lib/sandboxes/<sid>/tls/`.
   5. Open SSH tunnel to prod; mysqldump each DB with dump-only user.
   6. Bring up container bound to `127.0.0.1` only; restore dumps; run per-DB grants; stop.
   7. Restart with port published on `0.0.0.0:<host_port>`.
   8. Encrypt creds blob with Fernet; write row to SQLite with `status=ready`.
   9. Return response.
2. `GET /session/{id}` → decrypt creds, return same shape (no rotation).
3. `POST /session/{id}/reset-ttl` → if `ttl_extended == 0` and `now < max_extended_until`, set `expires_at = min(max_extended_until, expires_at + 2h)`, `ttl_extended = 1`. Else 409.
4. Reaper (every 30s) → for any `status=ready AND expires_at < now`: `docker compose down -v`, status `nuked`, log entry to `/var/log/sandboxes/reaper.log`. **Log bind-mount stays.**
5. `DELETE /session/{id}` → same as reaper, manual.

---

## 6. Container hardening

- Image: `mysql:8.4`.
- `user: "999:999"` (mysql user), `--cap-drop=ALL --security-opt no-new-privileges`.
- Resources: `--cpus=1.0 --memory=2g --pids-limit=256`.
- Ports: `3306 → ${HOST_PORT}:3306`, published on `0.0.0.0`.
- Volumes:
  - named vol `sandbox-<sid>-data` → `/var/lib/mysql` (destroyed on nuke)
  - bind `/var/log/sandboxes/<ticket>-<YYYY-MM-DD>/<sid>` → `/var/log/mysql` (persists)
  - bind `/var/lib/sandboxes/<sid>/tls` → `/etc/mysql/tls:ro`
  - bind `/var/lib/sandboxes/<sid>/mysqld.cnf` → `/etc/mysql/conf.d/sandbox.cnf:ro`
- `mysqld.cnf` sets `ssl-ca`, `ssl-cert`, `ssl-key`, `require_secure_transport=ON`, and disables `local_infile`.
- Grants per DB: `CREATE USER '...'; GRANT ALL ON <db>.* TO '...'@'%'; FLUSH PRIVILEGES;` — **no** `*.*`, **no** `SUPER`, **no** `PROCESS`, **no** `FILE`, **no** `GRANT OPTION`.

---

## 7. Production pull

- `ssh_tunnel.py` uses `paramiko` to open a local forward `127.0.0.1:<rand> → prod-mysql:3306` over SSH (key from `~/.ssh/sandbox_prod_ed25519`).
- MySQL user has only: `SELECT, LOCK TABLES, SHOW VIEW, EVENT, TRIGGER` on `*.*`. Dump only.
- Per DB: `mysqldump --single-transaction --quick --routines --triggers --events --no-tablespaces` piped through the tunnel.
- Restore into container on the temporary `127.0.0.1`-bound port.
- Tunnel closed **before** the container's port is published publicly.

---

## 8. State schema (SQLite)

```sql
CREATE TABLE sessions (
  id                    TEXT PRIMARY KEY,
  ticket                TEXT NOT NULL,
  date                  TEXT NOT NULL,                -- YYYY-MM-DD
  dbs_json              TEXT NOT NULL,                -- ["db_a","db_b"]
  creds_enc             BLOB NOT NULL,                -- Fernet(creds_json)
  host                  TEXT NOT NULL,
  port                  INTEGER NOT NULL,
  container_name        TEXT NOT NULL,
  compose_path          TEXT NOT NULL,
  tls_dir               TEXT NOT NULL,
  log_dir               TEXT NOT NULL,
  created_at            INTEGER NOT NULL,            -- epoch s
  expires_at            INTEGER NOT NULL,
  max_extended_until    INTEGER NOT NULL,
  ttl_extended          INTEGER NOT NULL DEFAULT 0,
  status                TEXT NOT NULL                 -- starting|ready|expired|nuked|error
);
CREATE INDEX idx_status_expires ON sessions(status, expires_at);
```

---

## 9. Auth model

> Updated after switching to Cloudflare front-end. **IP allowlist dropped** — Cloudflare hides the real client IP, so per-IP gating happens at the Cloudflare layer instead.

**Topology**

```
client ──HTTPS──▶ api-testdb.abc.co.zm  (Cloudflare HTTP proxy + TLS)
                     │
                     ├─ Cloudflare Access (SSO / IP / country policies)  ── injects Cf-Access-Jwt-Assertion
                     ▼
                  origin (this API)
                     │
                     └─ checks  Cf-Access-Jwt-Assertion  +  X-API-Key

client ──TLS──▶  <HOST_PUBLIC_IP>:<random_port>   (direct, no Cloudflare)
                     │
                     └─ MySQL container (self-signed TLS, per-DB scoped user)
```

**Origin checks (in this order)**

1. **Cloudflare Access JWT** in `Cf-Access-Jwt-Assertion` header. Verified against `SANDBOX_CF_ACCESS_AUD` (the Access Application AUD tag) and signature verified with the public key fetched from `SANDBOX_CF_ACCESS_CERTS_URL` (default `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`). Tokens are rejected if expired, wrong audience, or bad signature. *(This replaces the IP allowlist.)*
2. **`X-API-Key`** constant-time-compared against `SANDBOX_API_KEY`.
3. For the webhook trigger specifically, body HMAC-SHA256 verified with `SANDBOX_WEBHOOK_SECRET`, header `X-Sandbox-Signature: sha256=<hex>`.

`/healthz` is the only unauthenticated route.

**Why no IP allowlist in the API**

Because Cloudflare terminates the connection, `request.client.host` is always a Cloudflare edge IP. An IP allowlist in this code would only ever match Cloudflare's IP ranges, which is meaningless. Instead, IP / country / identity policies are configured at the Cloudflare Access layer (Cloudflare dashboard, not in this repo).

---

## 10. Security checklist

- [x] Per-DB MySQL user, no system grants.
- [x] Container non-root, all caps dropped, `no-new-privileges`.
- [x] Random public port; container published only after restore.
- [x] Prod access via SSH tunnel, dump-only MySQL user, tunnel closed pre-publish.
- [x] API key on every endpoint (constant-time compare).
- [x] Cloudflare Access JWT verified on every endpoint (identity / IP gating at the edge).
- [x] Credentials encrypted at rest (Fernet).
- [x] MySQL on public IP:port with self-signed TLS per container; per-DB scoped user.
- [x] TTL enforced by reaper; logs persist after nuke.

---

## 11. Open items (need from owner before going live)

| # | Item | Status |
|---|---|---|
| 1 | Prod MySQL host/port | pending |
| 2 | Prod MySQL dump-only username (or write GRANT for owner to apply) | pending |
| 3 | SSH target (bastion or direct) | pending |
| 4 | Host public IP for MySQL exposure | pending |
| 5 | Host port range for MySQL (default 33060–33999) | default ok |
| 6 | Fernet key (generated at bootstrap; placeholder in `.env.example`) | bootstrap |
| 7 | `SANDBOX_API_KEY` (generated at bootstrap) | bootstrap |
| 8 | Cloudflare Access: team domain (e.g. `myteam.cloudflareaccess.com`) + Application AUD tag | pending |
| 9 | Confirm prod-side column salting is in place | pending |
| 10 | DNS: `api-testdb.abc.co.zm` A record → host public IP | pending |

---

## 12. Implementation phases

> ✅ = done · 🚧 = in progress · ⬜ = pending

### Phase 0 — Bootstrap
- [x] Create `PLAN.md` ✅
- [x] Create empty `README.md`, `requirements.txt`, `.env.example`, `api/__init__.py`
- [x] Create `scripts/bootstrap.sh` skeleton
- [x] Create `tests/` directory with stub `conftest.py`

### Phase 1 — Config & crypto
- [x] `api/config.py` — pydantic-settings, all env vars
- [x] `api/crypto.py` — `gen_password`, `fernet_from_key`, `encrypt_creds`, `decrypt_creds`, `constant_time_eq`
- [x] `tests/test_crypto.py`

### Phase 2 — State store
- [x] `api/state.py` — schema init, CRUD, `claim_expired`, `mark_*` helpers
- [x] `tests/test_state.py`

### Phase 3 — Auth (Cloudflare Access JWT + API key)
- [x] `api/auth.py` — `enforce_cf_access`, `enforce_api_key`, `verify_webhook_signature`
- [x] `tests/test_auth.py` — JWT valid/expired/wrong-aud/bad-sig, API key, webhook HMAC
- [x] **No** allowlist file (dropped per owner decision; Cloudflare Access handles IP / identity gating)

### Phase 4 — TLS ops
- [x] `api/tls_ops.py` — `generate_session_tls(sid, dir)`
- [x] `tests/test_tls_ops.py`

### Phase 5 — SSH tunnel & mysql ops
- [x] `api/ssh_tunnel.py` — context manager wrapping paramiko forward
- [x] `api/mysql_ops.py` — `dump_db`, `restore_db`, `apply_grants`, `wait_ready`
- [x] `tests/test_mysql_ops.py` (mocked subprocess + fake paramiko)

### Phase 6 — Docker ops
- [x] `templates/docker-compose.yml.j2`
- [x] `templates/mysqld.cnf.j2`
- [x] `templates/grant_user.sql.j2`
- [x] `api/docker_ops.py` — `allocate_port`, `render_compose`, `up_session`, `down_session`, `replace_port_in_compose`

### Phase 7 — Reaper
- [x] `api/reaper.py` — `reap_once` + `reap_loop`
- [x] `tests/test_reaper.py`

### Phase 8 — FastAPI app & endpoints
- [x] `api/models.py` — Pydantic models
- [x] `api/service.py` — orchestration with DI
- [x] `api/main.py` — app, lifespan (start reaper), 7 routes
- [x] `tests/test_endpoints.py`

### Phase 11 — Ticket-closed webhook (added after phase 10)
- [x] `api/service.py` — `nuke_by_ticket(ticket, session_id)` — idempotent
- [x] `api/main.py` — `POST /webhook/ticket-closed` (HMAC only)
- [x] `api/models.py` — `TicketClosedRequest`, `TicketClosedResponse`
- [x] `tests/test_endpoints.py` — 7 new tests covering nuke, idempotency, mismatch, missing session, missing/bad signature, no-JWT-needed

### Phase 9 — Scripts & docs
- [x] `scripts/bootstrap.sh` — full impl
- [x] `scripts/run.sh`
- [x] `scripts/smoke.sh`
- [x] `README.md` — install, configure, run, examples

### Phase 10 — Verification
- [x] `pytest -q` passes (**82 tests**)
- [x] `bash -n` on every script
- [x] All `api/*.py` parse cleanly
- [x] FastAPI app boots and registers all 6 routes
- [ ] Manual smoke against a test MySQL (owner to run)

---

## 13. Environment variables

```
# .env.example — copy to .env and fill in

# === Auth ===
SANDBOX_API_KEY=                                  # openssl rand -hex 32
SANDBOX_WEBHOOK_SECRET=                           # openssl rand -hex 32

# Cloudflare Access (verify Cf-Access-Jwt-Assertion header)
SANDBOX_CF_ACCESS_AUD=                            # Application AUD tag from Cloudflare Access dashboard
SANDBOX_CF_ACCESS_CERTS_URL=                      # e.g. https://myteam.cloudflareaccess.com/cdn-cgi/access/certs

SANDBOX_FERNET_KEY=                               # python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# === Storage / paths ===
SANDBOX_STATE_DB=/var/lib/sandboxes/state.db
SANDBOX_COMPOSE_DIR=/var/lib/sandboxes/composes
SANDBOX_TLS_DIR=/var/lib/sandboxes/tls
SANDBOX_LOG_DIR=/var/log/sandboxes

# === Network ===
SANDBOX_PUBLIC_HOST=api-testdb.abc.co.zm          # API domain (Cloudflare HTTP proxy)
SANDBOX_MYSQL_HOST=                               # Host public IP returned to devs for MySQL connection
SANDBOX_PORT_RANGE_START=33060
SANDBOX_PORT_RANGE_END=33999

# === Prod access (SSH tunnel + dump-only MySQL user) ===
PROD_SSH_HOST=
PROD_SSH_USER=sandbox
PROD_SSH_KEY=/home/sandbox/.ssh/sandbox_prod_ed25519
PROD_SSH_PORT=22
PROD_MYSQL_HOST=
PROD_MYSQL_PORT=3306
PROD_MYSQL_USER=
PROD_MYSQL_PASSWORD=

# === Container / TTL ===
SANDBOX_MYSQL_IMAGE=mysql:8.4
SANDBOX_TTL_MIN_SECONDS=14400                    # 4h
SANDBOX_TTL_DEFAULT_SECONDS=21600                # 6h
SANDBOX_TTL_MAX_SECONDS=28800                    # 8h
SANDBOX_TTL_RESET_ADD_SECONDS=7200               # +2h on reset
SANDBOX_REAPER_INTERVAL_SECONDS=30
```

---

## 14. Progress log

| Date | Change |
|---|---|
| 2026-06-29 | Plan written. Phases 0–10 laid out. Awaiting green light + open items. |
| 2026-06-29 | Topology updated: API on `api-testdb.abc.co.zm` behind Cloudflare; MySQL on host public IP:port direct. IP allowlist dropped in favor of Cloudflare Access JWT verification. Added `Cf-Access-Jwt-Assertion` check + `SANDBOX_CF_ACCESS_AUD` / `SANDBOX_CF_ACCESS_CERTS_URL` env vars. `mysql_host` returned in `POST /instance` response. |
| 2026-06-29 | All 10 phases implemented. 82 pytest tests pass. `bash -n` clean. FastAPI app boots with 6 routes (`/healthz`, `/instance`, `GET /session/{id}`, `POST /session/{id}/reset-ttl`, `DELETE /session/{id}`, `GET /session-tls/{id}/ca.pem`). Scripts (`bootstrap.sh`, `run.sh`, `smoke.sh`) in place. README written. Awaiting deploy-time open items (§11) before going live. |
| 2026-06-29 | Phase 11: added `POST /webhook/ticket-closed` (HMAC-only auth, idempotent nuke keyed on ticket+session_id). 89 pytest tests pass.