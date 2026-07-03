# Changelog

All notable changes to this project are documented here. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are
implied by git tags; section headings below are the unreleased changes
pending the first tag.

---

## [Unreleased]

### Fixed (code)

- **`mysql_ops.dump_db`**: replaced dump-to-disk + read-back with a
  streaming `clone_db()` that pipes `mysqldump` directly into `mysql`
  on the sandbox. Removes the original 64 KB pipe-buffer deadlock from
  the `subprocess.run(..., capture_output=True)` implementation, removes
  the temp-file write/read entirely, and halves time-to-ready for big
  clones.
- **`mysql_ops.clone_db`, `restore_db`, `wait_ready`,
  `_ensure_database`, `apply_grants`** now accept `ssl_ca: Path |
  None`. Every client call into the sandbox now carries
  `--ssl-mode=REQUIRED --ssl-ca=<per-session ca.pem>`. The dump
  client keeps `--ssl-mode=DISABLED` because SSH encrypts the
  tunnel.
- **Docker healthcheck** (`templates/docker-compose.yml.j2`): removed
  the invalid `--default-authentication-plugin=caching_sha2_password`
  server flag and from the cnf; switched the healthcheck to a TLS
  call (`mysqladmin ping -h 127.0.0.1 -uroot -p… --ssl-mode=REQUIRED
  --ssl-ca=/etc/mysql/tls/ca.pem`); widened `start_period` to 180 s
  and `retries` to 60.
- **`docker_ops.wait_healthy`**: replaced the docker-healthcheck
  polling that ran into socket-permission issues on the API host with
  a JSON `docker inspect` for the published port + direct TCP probe
  against `127.0.0.1:<host_port>`. Falls back to TCP if the docker
  JSON parse fails, so a stale container does not block forever.
- **`state.SessionStore.claim_stuck`**: stuck-create detection now
  uses the row’s own `expires_at` instead of `created_at + grace`. The
  reaper `grace_seconds` is kept for compatibility but ignored.
- **`state.SessionStore.reserve_session`**: new sessions reserve
  `expires_at = now + 3600` so they survive the reaper during long
  dumps.
- **`reaper._teardown`**: short-circuits when the compose file is
  gone, so already-reaped sessions don’t keep firing errors on later
  reaper ticks.
- **`ssh_tunnel.open_tunnel`**: loads the system host keys before
  paramiko’s `RejectPolicy` so the bastion becomes a trustworthy peer
  after a one-time `ssh-keyscan` is committed to
  `/home/sandbox/.ssh/known_hosts`.

### Added (docs)

- `docs/USER_GUIDE.md` — developer-facing reference for the API
  (auth, every endpoint, request/response shapes, MariaDB vs MySQL
  client TLS flags, lifecycle, error-category table, cheat sheet).
- `docs/OPERATIONS.md` — platform-team runbook (bootstrap, reaper,
  mariadb:11.8 pin rationale, log locations, common failure-mode
  triage, key rotation, upgrade/rollback).
- `docs/SECURITY.md` — threat model, secret inventory, blast-radius
  per leaked credential, rotation cadence, incident checklist.
- `docs/CHANGELOG.md` — this file.

### Changed (ops)

- Pinned `SANDBOX_MYSQL_IMAGE=mariadb:11.8`. Earlier floating tags
  (`mysql:8.4`, `mysql:8.0`, `mariadb:10.11`) failed on prod dumps
  because the prod `MariaDB 11.8.5` server carries both `utf8mb3/4
  _uca1400_*` and `utf8mb3/4 _0900_*` collation families — only
  the 11.8 image includes the full set.
- `scripts/bootstrap.sh`: relax `state_dir` and `tls_dir` mode from
  `0750` to `0770` (the `sandbox` user needs to write CN files into
  `/var/lib/sandboxes/tls`); `pip install --ignore-installed` so the
  pinned versions in `requirements.txt` win against system packages
  that ship older ones.

### Removed

- The on-disk dump file path (`mysql_ops.dump_db` writing to
  `tempfile.NamedTemporaryFile(...)`) is no longer reachable from
  any caller — `SessionService._do_create` calls `clone_db` directly.
- A `sed`-based collation rewriter that was used to test the
  streaming path against `mysql:8.4` was reverted before this
  release. It is not safe: it modifies semantics of the dump and the
  fix is at the image level, not the SQL stream.

### Compatibility

- All `SessionService` and `mysql_ops` keyword arguments added
  (`ssl_ca`, `clone_db`) default to `None` / backward-compatible.
- Existing `tests/test_endpoints.py` test mocks that don’t pass a
  `clone_db` keep passing unchanged.
- Per-session TLS cert SANs were widened to include `127.0.0.1` so
  the API host’s loopback mysql client can verify the cert hostname
  with `--ssl-mode=REQUIRED --ssl-ca=<ca.pem>`.

### Known caveats

- `--forwarded-allow-ips='*'` in the systemd unit is wide; tighten
  to `127.0.0.1` (or the nginx upstream IP) in deployments where
  uvicorn is internet-facing.
- `state.db` is **forward-compatible only**: rolling back to a much
  older code revision can crash on read because schema migrations
  aren’t yet versioned in `state.py`.
- The sandbox image (`mariadb:11.8`) drifts over time as the
  upstream `mariadb` Docker tag pulls new builds. When prod upgrades,
  bump `SANDBOX_MYSQL_IMAGE` in lockstep.

---

## [0.0.0] — initial commit `87757fc`

Skeleton scaffold only; no live-tested integration with prod.
