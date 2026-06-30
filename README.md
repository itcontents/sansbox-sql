# sansbox-sql

A FastAPI service that provisions short-lived, isolated MySQL sandbox containers for debugging production data without exposing production.

Each ticket creates a per-session MySQL container populated from anonymized production DBs, exposes it on a random TLS-protected port on the host's public IP, hands the developer a per-DB scoped MySQL user, and auto-destroys the container at TTL while keeping an audit-friendly log bind-mount.

The API itself sits behind Cloudflare (HTTP proxy + Cloudflare Access JWT) at `api-testdb.abc.co.zm`.

See **`PLAN.md`** for the full design.

---

## Architecture (one-paragraph)

```
ticket-system ──HTTPS──▶ api-testdb.abc.co.zm  (Cloudflare: Access + HTTP proxy)
                              │
                              ▼
                          FastAPI (this repo)
                              │
                              ├── SSH tunnel  ──▶  prod bastion  ──▶  prod MySQL
                              │     (one-shot, dump-only MySQL user)
                              ▼
                          per-session MySQL container
                              │   bind-mount:  /var/log/sandboxes/<ticket>-<date>/<sid>
                              │   named vol:   sandbox-<sid>-data (destroyed on nuke)
                              ▼
                       <host_public_ip>:<random_port>  ──▶  developer
                              │   self-signed TLS per session, scoped user per DB
                              ▼
                          dev client (mysql --ssl-ca=ca.pem)
```

---

## Quick start

```bash
# 1. one-time host prep (creates dirs, user, generates secrets, installs deps,
#    renders deploy/nginx/sqldb-sandbox.conf and the systemd unit)
sudo bash scripts/bootstrap.sh

# 2. edit / fill in the placeholders in .env (see "Configuration" below)
sudo -e .env

# 3. provision TLS cert (Let's Encrypt):
sudo certbot --nginx -d api-testdb.abc.co.zm
# OR upload a Cloudflare Origin CA cert to the SANDBOX_NGINX_SSL_* paths,
# then re-run bootstrap so nginx picks them up.

# 4. start the API. With systemd:
sudo systemctl enable --now sqldb-sandbox
sudo journalctl -u sqldb-sandbox -f
# OR foreground:
bash scripts/run.sh

# 5. smoke test (assumes nginx + API are up; hits /healthz over HTTPS)
bash scripts/smoke.sh
```

Topology installed by bootstrap:
```
client ──HTTPS──▶ Cloudflare (DNS + SSL only, grey-clouded)
                       │
                       ▼
   host_public_ip:443 ──▶ nginx (deploy/nginx/sqldb-sandbox.conf)
                              │  proxy_pass http://127.0.0.1:8080
                              ▼
                           uvicorn 127.0.0.1:8080
                              │
                              └──▶ ssh tunnel ──▶ prod bastion ──▶ prod MySQL
                                                            │
                                                            └──▶ per-session MySQL containers
```

---

## Configuration (`.env`)

All env vars are listed in `.env.example`. Required fields (no default):

| Var | Purpose |
|---|---|
| `SANDBOX_API_KEY` | Static API key, `X-API-Key` header. Generated at bootstrap. |
| `SANDBOX_WEBHOOK_SECRET` | HMAC secret for the ticket-system webhook trigger. |
| `SANDBOX_FERNET_KEY` | Fernet key for encrypting session credentials at rest. |
| `SANDBOX_PUBLIC_HOST` | API hostname (`api-testdb.abc.co.zm`). Returned in `ca_url`. |
| `SANDBOX_MYSQL_HOST` | Host public IP returned to devs for MySQL connections. |
| `PROD_SSH_HOST`, `PROD_SSH_USER`, `PROD_SSH_KEY`, `PROD_SSH_PORT` | SSH bastion details. |
| `PROD_MYSQL_HOST`, `PROD_MYSQL_PORT`, `PROD_MYSQL_USER`, `PROD_MYSQL_PASSWORD` | Prod dump-only MySQL user. |

Optional tuning:

| Var | Default | Purpose |
|---|---|---|
| `SANDBOX_PORT_RANGE_START` / `_END` | 33060 / 33999 | Random host port range for MySQL publishing. |
| `SANDBOX_TTL_MIN_SECONDS` | 14400 (4h) | Minimum TTL floor. |
| `SANDBOX_TTL_DEFAULT_SECONDS` | 21600 (6h) | Default TTL at creation. |
| `SANDBOX_TTL_MAX_SECONDS` | 28800 (8h) | Hard ceiling after one reset. |
| `SANDBOX_TTL_RESET_ADD_SECONDS` | 7200 (2h) | Amount added on a `reset-ttl` call. |
| `SANDBOX_REAPER_INTERVAL_SECONDS` | 30 | How often the background reaper sweeps. |
| `SANDBOX_CF_ACCESS_AUD` | unset | Optional. Cloudflare Access Application ID (AUD tag). When both CF Access vars are set, the `Cf-Access-Jwt-Assertion` header is verified. Leave unset to skip CF Access entirely. |
| `SANDBOX_CF_ACCESS_CERTS_URL` | unset | Optional. Cloudflare JWKS URL (e.g. `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`). |
| `SANDBOX_TEST_MODE` | `0` | Set to `1` to skip **all** auth (CF Access, API key, webhook HMAC). Local testing only. |

---

## API

All routes require `X-API-Key` except `/healthz` and `/webhook/ticket-closed`.

If `SANDBOX_CF_ACCESS_AUD` and `SANDBOX_CF_ACCESS_CERTS_URL` are both set, every route additionally requires `Cf-Access-Jwt-Assertion`. Leave them blank to skip Cloudflare Access verification (Cloudflare is then only used for DNS/SSL).

### `POST /instance`
Create a sandbox session.

Each entry in `dbs` is either:
- a bare string (`"db_a"`) — full DB dump, or
- an object (`{"name": "db_a", "tables": [...]}`) — partial dump of just those tables.

`tables` accepts:
- a list of table names → dump only those tables from prod and restore only those tables into the sandbox
- `"all"` (or omitted) → dump the entire DB

```bash
# Full dump of two DBs
curl -X POST https://api-testdb.abc.co.zm/instance \
  -H 'X-API-Key: <key>' \
  -H 'Content-Type: application/json' \
  -d '{"ticket":"10215","dbs":["db_a","db_b"]}'

# Partial: only "orders" + "users" from db_a, entire db_b
curl -X POST https://api-testdb.abc.co.zm/instance \
  -H 'X-API-Key: <key>' \
  -H 'Content-Type: application/json' \
  -d '{
    "ticket":"10215",
    "dbs":[
      {"name":"db_a","tables":["orders","users"]},
      {"name":"db_b","tables":"all"}
    ]
  }'
```

If CF Access is configured, also send `-H 'Cf-Access-Jwt-Assertion: <JWT>'`.

Response 201:
```json
{
  "session_id": "f1c8...",
  "api_host": "api-testdb.abc.co.zm",
  "mysql_host": "203.0.113.10",
  "mysql_port": 33451,
  "expires_at": "2026-06-29T18:42:00Z",
  "max_extended_until": "2026-06-29T20:42:00Z",
  "ca_url": "https://api-testdb.abc.co.zm/session-tls/f1c8.../ca.pem",
  "databases": [
    { "name": "db_a", "user": "u_db_a_3kf2", "password": "...", "tables": ["orders","users"] },
    { "name": "db_b", "user": "u_db_b_8zx1", "password": "...", "tables": null }
  ]
}
```

`tables` is `null` when the whole DB was dumped.

### `GET /session/{session_id}`
Re-fetch creds for a live session.

### `POST /session/{session_id}/reset-ttl`
One-shot extension. Bumps `expires_at` by `SANDBOX_TTL_RESET_ADD_SECONDS` (capped at `max_extended_until`). Returns 409 if already used.

### `DELETE /session/{session_id}`
Manually destroy the container. Logs persist.

### `GET /session-tls/{session_id}/ca.pem`
Returns the per-session CA cert so the dev can pin TLS:
```bash
curl -fsSL https://api-testdb.abc.co.zm/session-tls/<sid>/ca.pem -o ca.pem
mysql --ssl-ca=ca.pem --ssl-mode=REQUIRED \
  -h <mysql_host> -P <mysql_port> -u <user> -p
```

### `POST /webhook/ticket-closed`
Ticket system calls this when a ticket is closed. Idempotent — nukes the session, no-op if already nuked. **HMAC-only auth** (no CF Access JWT, no API key — the ticket system may not have them).

Body must be signed with `SANDBOX_WEBHOOK_SECRET`, header `X-Sandbox-Signature: sha256=<hex>`.

```bash
BODY='{"ticket":"10215","session_id":"f1c8..."}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SANDBOX_WEBHOOK_SECRET" -hex | awk '{print $2}')"
curl -X POST https://api-testdb.abc.co.zm/webhook/ticket-closed \
  -H "Content-Type: application/json" \
  -H "X-Sandbox-Signature: $SIG" \
  -d "$BODY"
```

Response 200:
```json
{ "ticket": "10215", "session_id": "f1c8...", "status": "nuked" }
```
`status` is `"already_nuked"` on subsequent calls. 404 if `session_id` does not belong to the given ticket.

### `GET /healthz`
Liveness. No auth. Process-up only.

### `GET /readyz`
Readiness. No auth. Probes the SQLite store, the Docker daemon, and the
mysql/mysqldump/mysqladmin binaries. Returns `200 {status:ok}` or
`503 {status:degraded}` with a per-check breakdown.

### `GET /metrics`
Prometheus-format text. No auth. Counter `sqldb_sandbox_sessions_total`,
`sqldb_sandbox_sessions_by_status{status=...}`, and
`sqldb_sandbox_oldest_ready_seconds`. Firewall this at the nginx layer.

---

## Client workflow

```bash
SID=...
curl -fsSL https://api-testdb.abc.co.zm/session-tls/$SID/ca.pem -o ca.pem
mysql --ssl-ca=ca.pem --ssl-mode=REQUIRED \
  -h 203.0.113.10 -P 33451 -u u_db_a_3kf2 -p db_a
```

---

## Production access (security model)

- API opens a **one-shot SSH tunnel** to the prod bastion via the system user's `~/.ssh/sandbox_prod_ed25519`.
- The prod MySQL user has **dump-only** grants:
  ```sql
  GRANT SELECT, LOCK TABLES, SHOW VIEW, EVENT, TRIGGER ON *.* TO 'dumper'@'%';
  ```
- Tunnel is closed **before** the sandbox MySQL port is published publicly.
- Sensitive columns in prod are **already salted** before this service runs (out of scope here).

---

## Sandbox container hardening

- Image: `mysql:8.4`, runs as UID 999 (mysql user).
- All Linux caps dropped, `no-new-privileges`, 1 CPU, 2 GB RAM, 256 PIDs.
- `require-secure-transport=ON` — TLS required.
- `local_infile=0` — no client-side `LOAD DATA LOCAL`.
- Per-DB MySQL user only: `GRANT ... ON <db>.*` — no `*.*`, no `SUPER`/`PROCESS`/`FILE`.

---

## Tests

```bash
python3 -m pytest -q        # 82 tests, ~10s
```

Unit tests cover config validation, credential encryption, session store CRUD, reaper, JWT/API-key/webhook auth, TLS cert generation, MySQL/SQL exec wrappers (mocked), docker compose template rendering, and end-to-end endpoint contracts.

---

## File layout

```
api/                  FastAPI service
  config.py           env-driven Settings (pydantic)
  crypto.py           Fernet, passwords, webhook HMAC
  state.py            SQLite session store (thread-safe, WAL)
  auth.py             CF Access JWT verify (optional) + API key + body middleware
  tls_ops.py          per-session CA + leaf certs
  ssh_tunnel.py       paramiko local forward
  mysql_ops.py        mysqldump / mysql / mysqladmin wrappers
  docker_ops.py       compose + cnf + grant rendering, port allocation
  reaper.py           background TTL sweeper
  service.py          orchestration (DI-friendly)
  main.py             FastAPI app + lifespan + routes
  models.py           Pydantic request/response
templates/            Jinja2 templates rendered per session
  docker-compose.yml.j2
  mysqld.cnf.j2
  grant_user.sql.j2
deploy/
  nginx/sqldb-sandbox.conf    rendered into /etc/nginx/sites-available/
  systemd/sqldb-sandbox.service
scripts/              bootstrap.sh, run.sh, smoke.sh
tests/                pytest suite
PLAN.md               design + progress
```

---

## Operational notes

- Logs: per session under `/var/log/sandboxes/<ticket>-<YYYY-MM-DD>/<sid>/`. Persist after nuke. `error.log`, `slow.log`, `general.log`. Rotated by `deploy/logrotate/sqldb-sandbox` (installed by bootstrap): daily, 14-day retention, compressed.
- DB data volumes: `sandbox-<sid>-data` named volumes; destroyed on nuke.
- Reaper interval is configurable; defaults to 30s. Runs `down_session` for expired + orphan sessions concurrently on 4-worker thread pool.
- Composites stored under `/var/lib/sandboxes/composes/<sid>/` for forensics.
- TLS material kept under `/var/lib/sandboxes/tls/<sid>/` for the duration of the session.
- **state.db backup** (`scripts/backup-state.sh`): safe online snapshot via `sqlite3 .backup`; wire to a cron entry. Default retention: 7 days. Configurable via `SANDBOX_BACKUP_DIR` / `SANDBOX_BACKUP_RETENTION_HOURS`. Add to `/etc/cron.d/sqldb-sandbox`:
  ```
  0 * * * * root /opt/sqldb-sandbox-setup/scripts/backup-state.sh
  ```
- **/readyz** is the right endpoint for a Kubernetes-style readiness probe — returns 503 when SQLite, the Docker daemon, or mysql/* binaries are missing.
- **/metrics** is unauthenticated; firewall it at the nginx layer (`limit_except GET { deny all; }` already on the location; if you want to hide internal IPs, restrict by `allow`/`deny` per network).
- systemd unit caps the service at 2 GB RAM, 200 % CPU, 512 tasks. A runaway `mysqldump` will hit `MemoryMax` before it can OOM-kill the host.

## Failure handling

Every `POST /instance` persists a placeholder row as `status=starting` *before* any side-effecting work (SSH, mysqldump, docker, mysql). On any exception mid-flight:
1. The container is torn down (`docker compose down -v`).
2. The session row is set to `status=error`.
3. The response is one of `502 dump|container|restore|grant|ssh`, `503 port`, or `500 internal`. The body is a generic message — full stderr stays in the API logs.

The reaper also sweeps rows in `starting` or `error` past a 5-minute grace and nukes them with `-v`, so a process crash mid-create is not a leak.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `cf access jwks unreachable` 503 | Cloudflare Access URL wrong or network blocked. |
| `cf access token invalid` 401 | JWT expired, wrong audience, or wrong team. |
| `docker compose up failed` | Check `docker compose version`, image pull network, ports range exhaustion. |
| `mysqldump failed` | Prod creds, prod firewall, SSH key not on bastion authorized_keys. |
| Sessions stuck in `starting` | Check reaper logs; bring up container manually to inspect. |