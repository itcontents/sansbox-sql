# sqldb-sandbox — Developer User Guide

This guide is for **developers** who need to use the sqldb-sandbox API to
spin up a per-ticket MySQL sandbox populated from production data. It covers
the auth flow, every endpoint, the request/response shapes, the TLS dance
on the wire, the sandbox lifecycle, and how to debug a bad request.

The system design itself is documented in `../README.md` and `../PLAN.md`;
this document is the operational quick-start.

---

## TL;DR

```bash
# 1. create a sandbox from one ticket
curl -sS -X POST https://api-testdb.abc.co.zm/instance \
  -H "X-API-Key: ${SANDBOX_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"ticket":"smoke-001","dbs":[{"name":"8047610331","tables":["completedsale","stock"]}]}'

# 2. fetch the per-session CA cert
curl -sS -H "X-API-Key: ${SANDBOX_API_KEY}" \
  -o ca.pem \
  https://api-testdb.abc.co.zm/session-tls/<session_id>/ca.pem

# 3. connect (MariaDB client flags)
mysql -h 95.216.244.41 -P <mysql_port> \
  -u <db_user> -p<password> \
  --ssl --ssl-verify-server-cert --ssl-ca=ca.pem

# 4. when you're done, tear it down
curl -sS -X DELETE -H "X-API-Key: ${SANDBOX_API_KEY}" \
  https://api-testdb.abc.co.zm/session/<session_id>
```

---

## Authentication

All `/instance` and `/session/*` endpoints are double-gated.

| Layer | Header | When it’s required |
| --- | --- | --- |
| Static API key | `X-API-Key: <SANDBOX_API_KEY>` | always |
| Cloudflare Access | `Cf-Access-Jwt-Assertion: <jwt>` | only if `SANDBOX_CF_ACCESS_AUD` + `SANDBOX_CF_ACCESS_CERTS_URL` are both set on the server |
| `/webhook/ticket-closed` | HMAC signature header (see below) | instead of the above |

If you get back `{"detail":"invalid or missing API key"}`, the API key is
wrong or missing. If you get back an empty/non-JSON response with HTTP 401
and a Cloudflare page, the JWT failed.

### Webhook signature

The ticket-closed webhook is verified by an HMAC of the request body:

```
X-Webhook-Signature: sha256=<hex hmac-sha256 of body using SANDBOX_WEBHOOK_SECRET>
```

The HMAC secret is your `SANDBOX_WEBHOOK_SECRET`. Compute it server-side or
from the ticket-system before posting.

---

## Endpoints

| Method | Path | Purpose | Auth |
| --- | --- | --- | --- |
| `GET`  | `/healthz` | shallow liveness (no deps) | none |
| `GET`  | `/readyz`  | deep readiness (docker / sqlite / mysql client) | none |
| `GET`  | `/metrics` | Prometheus-style scrape | none |
| `POST` | `/instance` | create a new sandbox for a ticket | API key (+ optional CF JWT) |
| `GET`  | `/session/{sid}` | view one sandbox | API key (+ optional CF JWT) |
| `POST` | `/session/{sid}/reset-ttl` | add `SANDBOX_TTL_RESET_ADD_SECONDS` to the sandbox | API key (+ optional CF JWT) |
| `DELETE` | `/session/{sid}` | nuke one sandbox immediately | API key (+ optional CF JWT) |
| `GET`  | `/session-tls/{sid}/ca.pem` | download the per-session CA cert | API key (+ optional CF JWT) |
| `POST` | `/webhook/ticket-closed` | ticket system tells us the dev left | HMAC signature |

Server uses these status codes:

| Code | Meaning |
| --- | --- |
| `200` | success |
| `201` | created (POST `/instance`, POST `/webhook/ticket-closed`) |
| `401` | missing/invalid API key, Cloudflare JWT, or webhook signature |
| `404` | unknown session id |
| `409` | reset-ttl conflict (already extended or hit max-extended cap) |
| `410` | TLS material deleted |
| `422` | request payload failed schema validation |
| `500` | unclassified server bug — see logs |
| `502` | upstream failure — one of `ssh`, `dump`, `container`, `restore`, `grant` |
| `503` | port pool exhausted |

For 502/503 the response body includes a `category` field. Categories:

| category | meaning |
| --- | --- |
| `ssh` | the SSH tunnel to the bastion could not be opened |
| `dump` | `mysqldump` against prod failed or table names did not match |
| `container` | docker compose up failed, container crashed, or health probe timed out |
| `restore` | piping into the sandbox `mysql` failed (e.g. collation, TLS, auth) |
| `grant` | applying per-DB grants inside the sandbox failed |
| `port` | no free host port in the configured range |
| `internal` | unclassified bug — file a ticket with the response body |

---

## `POST /instance` — create a sandbox

### Request body

```json
{
  "ticket": "smoke-001",
  "dbs": [
    {
      "name": "8047610331",
      "tables": ["completedsale", "stock"]
    },
    {
      "name": "another_db"
    }
  ]
}
```

`dbs` is a list of `DBSpec`:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `name` | string | yes | the prod database name (`8047610331` in the example) |
| `tables` | list of string | no | if present, only these tables are dumped (partial dump); if absent or empty, the full DB is cloned |

`ticket` becomes the audit trail — every session row is keyed by
`(ticket, session_id)`.

### Response 201 Created

```json
{
  "session_id": "f5cc7703-6e98-429b-9d9e-271a381a93f4",
  "api_host": "api-testdb.abc.co.zm",
  "mysql_host": "95.216.244.41",
  "mysql_port": 33061,
  "expires_at": "2026-07-04T00:57:29Z",
  "max_extended_until": "2026-07-04T02:57:29Z",
  "ca_url": "https://api-testdb.abc.co.zm/session-tls/f5cc7703-6e98-429b-9d9e-271a381a93f4/ca.pem",
  "databases": [
    {
      "name": "8047610331",
      "user": "u_8047610331_72835824",
      "password": "vZLSsYuyntsZYBxIrq8WBShQefZc6DIt",
      "tables": ["completedsale", "stock"]
    }
  ]
}
```

`mysql_host` + `mysql_port` is where the sandbox listens on the public IP;
`user` / `password` are per-DB credentials with grants only on the
cloned database.

### Response 4xx / 5xx

```json
{
  "detail": "prod dump failed",
  "category": "dump",
  "session_id": "1988b8d2-3aeb-46e7-b31c-6f98c388435a",
  "hint": "see server logs for the full error"
}
```

If you pass a `tables` list and a name doesn’t exist on prod, you’ll get
HTTP 502 with `category: "dump"` and the API returns the mysqldump
error verbatim to logs, e.g.

```
mysqldump: Couldn't find table: "cashupcash"
```

Re-run after adjusting the table list (table names are case-sensitive
unless prod has `lower_case_table_names=1`).

---

## `GET /session/{session_id}` — view status

```bash
curl -sS -H "X-API-Key: $SANDBOX_API_KEY" \
  https://api-testdb.abc.co.zm/session/$SID
```

Returns the same shape as the create response plus the current lifecycle
state:

```json
{
  "session_id": "f5cc7703-6e98-429b-9d9e-271a381a93f4",
  "ticket": "smoke-001",
  "status": "ready",
  "api_host": "api-testdb.abc.co.zm",
  "mysql_host": "95.216.244.41",
  "mysql_port": 33061,
  "expires_at": "2026-07-04T00:57:29Z",
  "max_extended_until": "2026-07-04T02:57:29Z",
  "ttl_extended": false,
  "ca_url": "https://api-testdb.abc.co.zm/session-tls/f5cc7703-6e98-429b-9d9e-271a381a93f4/ca.pem",
  "databases": [
    {
      "name": "8047610331",
      "user": "u_8047610331_72835824",
      "password": "vZLSsYuyntsZYBxIrq8WBShQefZc6DIt",
      "tables": ["completedsale", "stock"]
    }
  ]
}
```

`status` is one of `starting`, `ready`, `expired`, `nuked`, `error`.

---

## `POST /session/{session_id}/reset-ttl`

Add `SANDBOX_TTL_RESET_ADD_SECONDS` (default 7200s) to the active TTL.

```bash
curl -sS -X POST -H "X-API-Key: $SANDBOX_API_KEY" \
  https://api-testdb.abc.co.zm/session/$SID/reset-ttl
```

Response 200:

```json
{
  "session_id": "…",
  "expires_at": "2026-07-04T02:57:29Z",
  "max_extended_until": "2026-07-04T04:57:29Z",
  "reset_used": true
}
```

Returns HTTP 409 (`cannot reset ttl …`) if the sandbox is not in
`ready`, the TTL was already extended once, or `expires_at` is already at
`max_extended_until`.

---

## `DELETE /session/{session_id}` — nuke

```bash
curl -sS -X DELETE -H "X-API-Key: $SANDBOX_API_KEY" \
  https://api-testdb.abc.co.zm/session/$SID
```

Response 200:

```json
{ "session_id": "…", "status": "nuked" }
```

Idempotent: nuking an already-nuked session still returns the same
`nuked` status.

---

## `GET /session-tls/{session_id}/ca.pem` — per-session CA

The sandbox MySQL runs with `require-secure-transport=ON` and a self-signed
cert issued by a per-session CA. **The CA is unique to the session**, so
you must fetch it from this endpoint and pass it to your client. Without
it the client refuses to trust the server cert.

```bash
curl -sS -H "X-API-Key: $SANDBOX_API_KEY" \
  -o ca.pem \
  https://api-testdb.abc.co.zm/session-tls/$SID/ca.pem

ls -la ca.pem
head -1 ca.pem         # should be "-----BEGIN CERTIFICATE-----"
```

The response is the file itself (`Content-Type: application/x-pem-file`),
not a JSON envelope.

---

## Connecting with your client

The sandbox MySQL is reachable on `mysql_host:mysql_port` from the public
network, requires TLS, and only accepts the per-DB user.

> **Important:** if you have a recent MySQL/MariaDB CLI installed via
> your distro, the TLS flags differ between them. The flags below target
> the MariaDB CLI shipped on Ubuntu 24.04.

### MariaDB client (`mariadb` / `mysql` on Ubuntu noble)

```bash
mysql -h "$mysql_host" -P "$mysql_port" \
  -u "$user" -p"$password" \
  --ssl --ssl-verify-server-cert --ssl-ca=ca.pem
```

### MySQL client (8.0+)

```bash
mysql -h "$mysql_host" -P "$mysql_port" \
  -u "$user" -p"$password" \
  --ssl-mode=VERIFY_CA --ssl-ca=ca.pem
```

You should land in the sandbox MariaDB 11.8. Test with:

```sql
SELECT VERSION();
SHOW DATABASES;
USE 8047610331;
SHOW TABLES;
```

If you see `ERROR 2026 (HY000): TLS/SSL error`, you’re missing the CA
file or the cert bundle is empty. If you see `unknown variable
'ssl-mode=REQUIRED'`, you’re on a MariaDB client and need the MariaDB
flags above. If you see `Host '95.216.244.41' is not allowed to connect`,
the API host is firewalled off from your network — connect from the
corp VPN or whichever egress the API host allows.

---

## Sandbox lifecycle

```
POST /instance
    │
    ▼
 starting            (placeholder row in state.db; container being built)
    │
    │  mysqldump prod │ streamed into sandbox mysql via the docker bridge
    ▼
 ready               (creds blob persisted; you can connect)
    │
    │  expires_at = created_at + SANDBOX_TTL_DEFAULT_SECONDS (default 21600 = 6h)
    │  max_extended_until = created_at + SANDBOX_TTL_MAX_SECONDS (default 28800 = 8h)
    │  one /reset-ttl call may bump expires_at up to max_extended_until
    ▼
 expired             (TTL reached, reaper tears down the container)
 nuked               (container destroyed; audit logs kept on host)
```

A reaper runs every `SANDBOX_REAPER_INTERVAL_SECONDS` and:

- nukes `starting`/`error` rows older than `expires_at`;
- transitions `ready` rows to `expired` and tears them down once
  `expires_at` passes.

If a session died mid-create (bad dump, OOM-killed container, network
blip), the placeholder row stays in `starting` until the reaper nukes it
on grace window. The original CREATE for such cases still surfaces a 502
to the client, and the operator can see `starting → nuked` transitions in
the logs.

---

## Examples

### Spin up a full-DB sandbox

```bash
curl -sS -X POST -H "X-API-Key: $SANDBOX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ticket":"TICK-1234","dbs":[{"name":"8047610331"}]}' \
  https://api-testdb.abc.co.zm/instance
```

### Spin up partial-table sandbox

```bash
curl -sS -X POST -H "X-API-Key: $SANDBOX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ticket":"TICK-1234","dbs":[{"name":"8047610331","tables":["completedsale","stock","stockeditlog"]}]}' \
  https://api-testdb.abc.co.zm/instance
```

### List tables before requesting a partial dump

Connect to an existing sandbox and inspect the table set:

```sql
USE 8047610331;
SHOW TABLES;
```

…then copy exact table names into the next `POST /instance`. Names are
case-sensitive.

### Auto-nuke when the ticket closes

Wire the ticket system to `POST /webhook/ticket-closed`:

```bash
BODY='{"ticket":"TICK-1234","session_id":"f5cc7703-6e98-429b-9d9e-271a381a93f4"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SANDBOX_WEBHOOK_SECRET" -hex | awk '{print $2}')
curl -sS -X POST \
  -H "X-Webhook-Signature: sha256=$SIG" \
  -H "Content-Type: application/json" \
  --data "$BODY" \
  https://api-testdb.abc.co.zm/webhook/ticket-closed
```

Response 200:
```json
{ "ticket": "TICK-1234", "session_id": "…", "result": "nuked" }
```

`result` can be `nuked` (active session was destroyed) or `already_nuked`
(idempotent re-call). HTTP 404 means `(ticket, session_id)` didn’t match
any known session — usually a stale session id was passed; verify with
`GET /session/{sid}` first.

---

## Common errors and what to do

| Symptom | HTTP | category | Likely cause | Fix |
| --- | --- | --- | --- | --- |
| `invalid or missing API key` | 401 | — | missing/wrong `X-API-Key` | check the env on your side; ask the platform team |
| `Cloudflare 403` | 403 | — | CF Access JWT missing/invalid | read the access policy doc |
| `prod dump failed` | 502 | `dump` | mysqldump error: bad name, bad chars, prod privileges | check the error in `journalctl -u sqldb-sandbox`; verify the table exists on prod |
| `no free sandbox ports; retry later` | 503 | `port` | sandbox port range is exhausted | wait for older sessions to expire; raise `SANDBOX_PORT_RANGE_END` |
| `could not reach the bastion` | 502 | `ssh` | bastion down or key permission | ask the platform team |
| `container startup failed` | 502 | `container` | container crashed (oom, bad cnf, etc.) | check `/var/log/sandboxes/<ticket>-<date>/<sid>/error.log` |
| `restore failed` | 502 | `restore` | collation mismatch / TLS handshake / perms | check sandbox image matches prod exactly (mariadb:11.8 for `11.8.x` MariaDB prod) |
| `applying permissions failed` | 502 | `grant` | grant statement rejected | rare; file a ticket with the response body |

### Deep-debug checklist

1. **Server-side logs**: `sudo journalctl -u sqldb-sandbox -n 200 --no-pager`
2. **Per-session logs**: `/var/log/sandboxes/<ticket>-<YYYY-MM-DD>/<sid>/{error.log,slow.log}`
3. **Live processes**: `ps -ef | grep -E 'uvicorn|mysqldump|ssh -N|docker'` — if
   `mysqldump` is alive longer than the data size warrants, the prod
   side is slow, not broken.
4. **Sandbox container**: `docker ps -a --filter name=sandbox-<sid>` —
   status should be `Up` and `(healthy)` once `ready`.
5. **DNS for `mysql_host`**: from your laptop, `dig +short $mysql_host` —
   if it doesn’t resolve, your network isn’t allowed to reach the API
   host.

---

## Cheat sheet

```
POST   /instance                create sandbox
GET    /session/<sid>           view status / creds
GET    /session-tls/<sid>/ca.pem  per-session CA cert
POST   /session/<sid>/reset-ttl  bump TTL by SANDBOX_TTL_RESET_ADD_SECONDS
DELETE /session/<sid>           nuke immediately
POST   /webhook/ticket-closed    HMAC-signed ticket-system callback

auth headers (always): X-API-Key: <SANDBOX_API_KEY>
auth headers (cloudflared):     Cf-Access-Jwt-Assertion: <jwt>
webhook auth:                  X-Webhook-Signature: sha256=<hmac of body>

connect (MariaDB client):
  mysql -h <mysql_host> -P <mysql_port> \
        -u <user> -p<password> \
        --ssl --ssl-verify-server-cert --ssl-ca=ca.pem

connect (MySQL 8 client):
  mysql ... --ssl-mode=VERIFY_CA --ssl-ca=ca.pem
```
