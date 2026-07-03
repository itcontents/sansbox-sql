# sqldb-sandbox — Platform Operations Runbook

This is the day-2 playbook for the platform team running `sqldb-sandbox`.
For the system overview see `../README.md`; for design rationale see
`../PLAN.md`; for end-developer usage see `./USER_GUIDE.md`.

Hosts touched:

| Path | Owner | Purpose |
| --- | --- | --- |
| `/opt/sqldb-sandbox-setup/` | `root:sandbox` (0775) | repo checkout + `.env` + systemd unit source |
| `/var/lib/sandboxes/` | `root:sandbox` (0770) | per-session compose files, TLS material, state DB |
| `/var/lib/sandboxes/composes/<sid>/` | sandbox | rendered `docker-compose.yml` and `mysqld.cnf` |
| `/var/lib/sandboxes/tls/<sid>/` | sandbox | CA, server, client certs for one session |
| `/var/lib/sandboxes/state.db` | sandbox | sqlite store of all sessions |
| `/var/log/sandboxes/<ticket>-<date>/<sid>/` | sandbox | MySQL `error.log` and `slow.log` (bind-mounted into the container) |
| `~/.ssh/sandbox_prod_ed25519` | `sandbox:sandbox` (0600) | SSH key for the prod bastion |

---

## Day-1 setup

`scripts/bootstrap.sh` is idempotent and re-runnable. Run as root:

```bash
cd /opt/sqldb-sandbox-setup
sudo bash scripts/bootstrap.sh
```

It does, in order:

1. Creates `sandbox` system user (no shell, no login).
2. Creates `/var/lib/sandboxes/` and `/var/log/sandboxes/` with
   `root:sandbox` group ownership and `0770` mode.
3. Adds `sandbox` to the `docker` group.
4. Checks `docker` and `docker compose` v2 are installed.
5. Checks `mysqldump`, `mysql`, `mysqladmin` are on PATH (warns if not).
6. Creates `/home/sandbox/.ssh/` if missing — you must drop the prod
   bastion key at `/home/sandbox/.ssh/sandbox_prod_ed25519` manually.
7. Copies `.env.example` → `.env` if missing; populates
   `SANDBOX_API_KEY`, `SANDBOX_WEBHOOK_SECRET`, `SANDBOX_FERNET_KEY` if
   they’re still placeholders; mode `0640` owned by `root:sandbox`.
8. Installs Python deps with `pip install --break-system-packages
   --ignore-installed -r requirements.txt`.
9. Runs the test suite (`pytest -q`). A failure warns but does not abort.
10. Renders the nginx site (only if nginx + SANDBOX_NGINX_* are configured
    and the cert/key files exist).

After bootstrap, fill in prod-side fields in `/opt/sqldb-sandbox-setup/.env`:

- `SANDBOX_MYSQL_HOST` — public IP devs hit; usually the host’s NIC.
- `PROD_SSH_HOST/PORT/USER/KEY` and `PROD_MYSQL_HOST/PORT/USER/PASSWORD`.
- `SANDBOX_NGINX_SSL_CERT/KEY` — only if you front with nginx + Let’s
  Encrypt / CF Origin CA.

Enable and start:

```bash
sudo systemctl enable --now sqldb-sandbox
sudo journalctl -u sqldb-sandbox -f
```

Wire the hourly state-DB backup (optional but recommended):

```cron
0 * * * * /opt/sqldb-sandbox-setup/scripts/backup-state.sh
```

---

## Service management

The unit file lives at `deploy/systemd/sqldb-sandbox.service`. The
installed unit is rendered by `bootstrap.sh` from
`/etc/systemd/system/sqldb-sandbox.service` with `__WORKING_DIR__`
substituted with `SANDBOX_WORKING_DIR`.

```ini
[Service]
User=sandbox
Group=sandbox
SupplementaryGroups=docker
WorkingDirectory=/opt/sqldb-sandbox-setup
EnvironmentFile=/opt/sqldb-sandbox-setup/.env
ExecStart=/usr/bin/python3 -m uvicorn api.main:app \
    --host 127.0.0.1 --port 8080 --workers 1 \
    --proxy-headers --forwarded-allow-ips='*' \
    --log-level info
Restart=on-failure
RestartSec=3
MemoryMax=2G
CPUQuota=200%
TasksMax=512
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/var/lib/sandboxes /var/log/sandboxes
```

### Common commands

```bash
sudo systemctl status sqldb-sandbox
sudo systemctl restart sqldb-sandbox
sudo journalctl -u sqldb-sandbox -n 200 --no-pager
```

When you upgrade code on disk, `git pull && sudo systemctl restart
sqldb-sandbox` is enough. After every `.env` change, `sudo systemctl
restart sqldb-sandbox` to reload `EnvironmentFile`.

### Health probes

```bash
curl -sS http://127.0.0.1:8080/healthz   # process is up
curl -sS http://127.0.0.1:8080/readyz    # docker + sqlite + mysql-client all reachable
curl -sS http://127.0.0.1:8080/metrics   # Prometheus-format counters
```

`/readyz` reports `200` when all three checks pass, `503` with a
`checks` payload when any is `fail`. Wire the external probe at
`/readyz`, not `/healthz`, so it actually catches the sandbox being
un-deployable.

---

## Reaper

Background task started inside the uvicorn lifespan (`api/reaper.py`).
It runs every `SANDBOX_REAPER_INTERVAL_SECONDS` (default 30) and does:

- nukes sessions with `status IN ('starting','error')` whose `expires_at`
  is in the past. `expires_at` is the authoritative “stuck-create”
  deadline — the row’s `expires_at = created_at + 3600s` is set at
  reserve time. A `restart` of the API doesn’t lose already-doomed rows.
- transitions `ready` → `expired` and tears down the container once
  `expires_at` passes; the row then becomes `nuked` after the docker
  compose down succeeds.

To debug a row in `starting`/`error`:

```bash
sudo sqlite3 /var/lib/sandboxes/state.db "SELECT id, ticket, status, created_at, expires_at FROM sessions WHERE status IN ('starting','error') ORDER BY created_at DESC LIMIT 10;"
```

To force-clear an orphan (only if you’ve confirmed the container is
already gone):

```bash
sid=0e4db220-9b9c-4bf9-a847-3ca4699dc6a8
sudo sqlite3 /var/lib/sandboxes/state.db "UPDATE sessions SET status='nuked' WHERE id='$sid';"
```

Be careful: editing `state.db` while the API holds a write transaction
can wedge sqlite. Run with the service stopped, or use `sqlite3 .backup
/var/lib/sandboxes/state.db` first and edit the copy.

---

## Sandbox MySQL image

Set via `SANDBOX_MYSQL_IMAGE` in `.env`. The default and recommended
value is `mariadb:11.8`; pin it explicitly:

```bash
echo 'SANDBOX_MYSQL_IMAGE=mariadb:11.8' | sudo tee -a /opt/sqldb-sandbox-setup/.env
sudo systemctl restart sqldb-sandbox
```

### Why `mariadb:11.8`

Production at the time of writing is `MariaDB 11.8.5`. The Docker Hub
`mariadb:11.8` tag is built from the same Ubuntu noble sources
(verified `11.8.8-MariaDB-ubu2404-log` on pull) and ships **both**
collation families you’ll see in prod dumps:

- `utf8mb4_0900_*` (MySQL 8.x vendored into MariaDB)
- `utf8mb3_0900_*`
- `utf8mb4_uca1400_*` / `utf8mb3_uca1400_*` (MariaDB 10.6+)

Other tags we tested and rejected:

| Tag | Why it doesn’t work |
| --- | --- |
| `mysql:8.0` | never had `utf8mb?_uca1400_*` collations; prod dumps with those names fail with `Unknown collation` |
| `mysql:8.4` | dropped most `uca1400_*` collations; `Unknown collation` on prod dumps |
| `mariadb:10.11` | missing the `uca1400` collation register; tables defined with `utf8mb4_uca1400_ai_ci` fail |
| `mariadb:11.8` | matches prod |

If you ever change prod, bump the pin here at the same time. Drift
between prod and sandbox image is what causes the `category: "restore"`
`Unknown collation` failures.

---

## TLS material

Per session the API generates:

- `ca.pem` / `ca.key` — root CA, valid 2 years, `path_length=0`.
- `server-cert.pem` / `server-key.pem` — server cert, valid 1 year,
  `SERVER_AUTH` EKU, SANs: container hostname, configured
  `mysql_host_ip` (`SANDBOX_MYSQL_HOST`), and `127.0.0.1` (loopback).
- `client-cert.pem` / `client-key.pem` — reserved for future use;
  per-DB user/password is used for auth today.

Stored under `/var/lib/sandboxes/tls/<sid>/`. Mode is `0644` for certs
and `0600` for keys; owner `sandbox` (the API process).

Docker-compose mounts that directory as `/etc/mysql/tls:ro` into the
container; the in-container healthcheck and the API host’s
`mysql --ssl-ca=...` calls all consume the same CA.

### What gets shared with the dev

The dev needs `ca.pem` only. They call
`GET /session-tls/{sid}/ca.pem` with their API key (which is what the
browser-equivalent host does for them via the `ca_url` returned in the
create response). The private key is **never** sent over the wire —
once the API host has issues it, the API host doesn’t need it again
(the container keeps the cert for one container lifetime).

If the per-session CA’s `127.0.0.1` SAN isn’t present, the API host
will fail TLS handshake on loopback. Recent versions of `api/tls_ops.py`
add that SAN automatically.

---

## Log locations

| Stream | Path | Notes |
| --- | --- | --- |
| API service | `journalctl -u sqldb-sandbox` | uvicorn + reaper logs; per-failure stack traces |
| Failed container | `/var/log/sandboxes/<ticket>-<date>/<sid>/error.log` | bind-mounted from `/var/log/mysql/` inside the container; container MySQL errors |
| Slow queries | `/var/log/sandboxes/<ticket>-<date>/<sid>/slow.log` | mirror of `/var/log/mysql/slow.log` |
| Config | `/var/lib/sandboxes/composes/<sid>/docker-compose.yml`, `…/mysqld.cnf` | the rendered config; useful to grep if a sandbox is misbehaving |
| TLS | `/var/lib/sandboxes/tls/<sid>/` | CA + server + client certs for the session |
| Live processes | `ps -ef | grep -E 'uvicorn|mysqldump|ssh -N'` | the active pipeline at any moment |
| Log rotation | `deploy/logrotate/sqldb-sandbox` | installed by bootstrap; daily, 14-day retention, gzipped |

### Per-sandbox forensics

For an in-flight or failed session:

```bash
sid=0e4db220-9b9c-4bf9-a847-3ca4699dc6a8
ls -la /var/lib/sandboxes/composes/$sid/         # rendered config
ls -la /var/lib/sandboxes/tls/$sid/              # TLS material
ls -la /var/log/sandboxes/*/$sid/                # container logs
journalctl -u sqldb-sandbox | grep $sid          # trace the request
```

To replay the create against an active failure: the rendered `docker-compose.yml`
is plain YAML, so you can `cd` into that directory and `docker compose ps` /
`docker compose logs` for raw container output.

---

## Backup and restore

`scripts/backup-state.sh` runs hourly via cron (you wire it during
setup). Each run:

1. `sqlite3 .backup` writes a WAL-consistent snapshot to
   `/var/lib/sandboxes/backups/state-<UTC>.db.partial`, then renames.
2. Copies the `-wal` file alongside (defensive; usually empty).
3. Prunes snapshots older than `SANDBOX_BACKUP_RETENTION_HOURS`
   (default 168 = 7 days).

Snapshot files are root-readable only; permissions are inherited from
the cron job.

To recover from a corrupted `state.db`:

```bash
sudo systemctl stop sqldb-sandbox
sudo -u sandbox sqlite3 /var/lib/sandboxes/state.db ".restore '/var/lib/sandboxes/backups/state-YYYYMMDDTHHMMSSZ.db'"
sudo systemctl start sqldb-sandbox
```

WAL files are not part of `.restore`; if the prod DB was actively being
mutated at backup time, you may need to `sqlite3 $DB ".recover"` against
the latest snapshot + the next WAL file.

Note: backups cover only the **state.db**. They do not include
per-session docker-compose files, TLS material, log bind-mounts, or
MySQL data volumes — those are intentionally ephemeral and recreated on
each new create. Backups are not for restoring a specific sandbox, only
the metadata of which sessions existed.

---

## Capacity and resource caps

The systemd unit caps the **API process** at `MemoryMax=2G CPUQuota=200%
TasksMax=512`. The **sandbox containers** are capped in
`templates/docker-compose.yml.j2`:

```yaml
cap_drop: [ALL]
pids_limit: 256
cpus: 1.0
mem_limit: 2g
```

Each sandbox mounts `log_dir` from the host — these grow over the
session’s TTL. If a sandbox is doing heavy writes, you’ll see logs eat
disk.

Host port range is set in `.env`:

```
SANDBOX_PORT_RANGE_START=33060
SANDBOX_PORT_RANGE_END=33999
```

If you bump these, also bump the firewall / nginx upstream range
allowlist. With `33999 - 33060 = 939` ports and a 6h default TTL, you can
have roughly `939 * (24 / 6) ≈ 3756` sandboxes/day before exhausting the
range — assuming sandboxes are nuked when the ticket closes (which the
webhook + ticket-system integration is supposed to do).

---

## Routine operations

### List active sessions

```bash
sudo sqlite3 /var/lib/sandboxes/state.db \
  "SELECT id, ticket, status, host, port, expires_at FROM sessions WHERE status NOT IN ('nuked','expired') ORDER BY created_at DESC LIMIT 50;"
```

### Force-nuke a session from the API host

Use the API:
```bash
curl -sS -X DELETE -H "X-API-Key: $SANDBOX_API_KEY" \
  https://127.0.0.1:8080/session/$sid
```

If the API is wedged but the container is fine, you can also do it
directly:
```bash
docker compose -f /var/lib/sandboxes/composes/$sid/docker-compose.yml down -v
sudo sqlite3 /var/lib/sandboxes/state.db "UPDATE sessions SET status='nuked' WHERE id='$sid';"
```

### Rotate `SANDBOX_API_KEY`

Two-step:
1. Update `/opt/sqldb-sandbox-setup/.env` with the new value.
2. Update each consumer (ticket-system, devs’ client scripts).
3. `sudo systemctl restart sqldb-sandbox`.

There is no overlap window. A consumer that still has the old key will
get `401` until it updates.

### Rotate `SANDBOX_WEBHOOK_SECRET`

Same procedure. Existing webhook integrations will fail signature
verification until they update.

### Rotate `SANDBOX_FERNET_KEY`

This one is destructive — the **existing sessions’ stored credentials
can no longer be decrypted**. Decide first whether to:
- keep the old key long enough to copy-decrypt-re-encrypt each session
  row, then swap, or
- nuke all sessions first (nuked session creds are irrelevant).

If in doubt: snapshot `state.db`, rotate the Fernet key, **nuke all
active sessions**, devs will need to re-create them.

### Rotate prod SSH key

```bash
sudo -u sandbox ssh-keygen -t ed25519 -N '' -f /home/sandbox/.ssh/sandbox_prod_ed25519.new
# upload the .new.pub to the bastion as an authorized principal
# swap files
sudo -u sandbox mv /home/sandbox/.ssh/sandbox_prod_ed25519{.new,}
sudo -u sandbox chmod 600 /home/sandbox/.ssh/sandbox_prod_ed25519
sudo systemctl restart sqldb-sandbox
```

### Rotate the per-session TLS chain (forced expiry)

Sandboxes issue per-session certs that live for one container
lifetime. There is no global rotation — every new session gets a
fresh CA. The CA key on disk is never exposed; once a session is
nuked its TLS material is kept around for forensics only.

---

## Common failure modes and what to do

### `create` returns `category: dump`

Check the journal entry; it includes mysqldump stderr verbatim.
Quickest fixes by symptom:

```
mysqldump: Got errno 11 on write    → restart didn't apply — confirm service was actually restarted.
mysqldump: Couldn't find table: …   → table name typo or wrong case; pass the literal SHOW TABLES result.
mysqldump: Access denied             → PROD_MYSQL_USER is not a dump-only user on prod; check grants.
```

### `create` returns `category: container`

```text
container startup failed
container sandbox-… did not become healthy in 600s
```

```bash
journalctl -u sqldb-sandbox -n 100 --no-pager | grep -A 30 "container"
ls /var/log/sandboxes/*/<sid>/error.log
```

If the error log says:

```
unknown variable 'default-authentication-plugin=caching_sha2_password'
```

→ someone re-introduced the bad cnf/compose line. `templates/mysqld.cnf.j2`
and `templates/docker-compose.yml.j2` should **not** carry that key.

If the error log says nothing about collation or auth and the host
spammed `Lost connection`, the container likely OOM-killed.
`mem_limit: 2g` should be ample for normal data; dump larger than that
needs a `mysqldump --where='1' LIMIT n` partial or a different sandbox
profile (currently no profile-selector route is wired, so use partial
`tables` instead).

### `create` returns `category: restore`

```text
ERROR 1273 (HY000): Unknown collation: 'utf8mb4_0xxx_xx_xx'
```

→ prod changed; the sandbox image dropped the collation. Update
`SANDBOX_MYSQL_IMAGE` to the matching tag and restart. Re-run.

### `category: port`

```text
no free sandbox ports; retry later
```

Either wait for old sandboxes to expire, or extend
`SANDBOX_PORT_RANGE_END` (and adjust upstream firewall/limits).

### `category: ssh`

```bash
sudo -u sandbox ssh -i /home/sandbox/.ssh/sandbox_prod_ed25519 \
    -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -p 2222 sandbox@<PROD_SSH_HOST> 'echo ok'   # if known_hosts entry exists
```

If the manual SSH fails, fix bastion connectivity before retrying.

### Container logs are missing

```bash
ls -la /var/lib/sandboxes/composes/$sid/
ls -la /var/log/sandboxes/*/$sid/
```

If `composes/$sid/` is gone, the reaper already cleaned it up. If
`log/smoke-X/.../<sid>/` is gone, `logrotate`/`/var/log` pressure
pruned it; check `/var/log/sandboxes` perms, host disk space.

### API won’t start

```bash
sudo systemctl status sqldb-sandbox
sudo journalctl -u sqldb-sandbox -n 100 --no-pager
```

Common patterns:

- `python3: can't open file '/opt/sqldb-sandbox-setup/api/main.py'` →
  repo path moved; re-render systemd unit, `daemon-reload`, restart.
- `ModuleNotFoundError: fastapi` → bootstrap pip ran but venv is being
  preferred in `PYTHONPATH`; check `Environment=` in the unit.
- `.env: permission denied` → `.env` mode wrong; ensure
  `chmod 0640 root:sandbox`.

---

## Upgrades and rollback

```bash
cd /opt/sqldb-sandbox-setup
git fetch
git log --oneline origin/main -10
```

To bring code up to date:
```bash
git pull --rebase
sudo systemctl restart sqldb-sandbox
journalctl -u sqldb-sandbox -n 200 --no-pager
```

To roll back:
```bash
git checkout <previous-sha>
sudo systemctl restart sqldb-sandbox
```

`state.db` is **forward-compatible only**: rolling back to a much
older code revision that has different schema expectations can
crash on read. After backing up `state.db`, prefer to upgrade/downgrade
schema migrations one step at a time rather than across multiple
revisions.

---

## Pointers

- Source of truth for the system design: `../README.md` and `../PLAN.md`.
- Dev-facing API docs: `./USER_GUIDE.md`.
- Tests that exercise the same code paths: `pytest -q` from the repo
  root. Run after every schema-affecting change; new tests are welcome.
- Docker images used: `mariadb:11.8` (sandbox), the API uses
  `cryptography`, `paramiko`, `fastapi`, `uvicorn`, `jinja2`.
- External integrations: Cloudflare Access (optional, JWT in
  `Cf-Access-Jwt-Assertion`), Cloudflare/nginx for TLS termination.
- The team that owns prod access: whoever runs the bastion at
  `PROD_SSH_HOST:PROD_SSH_PORT`.
