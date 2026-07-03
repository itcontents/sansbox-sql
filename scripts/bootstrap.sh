#!/usr/bin/env bash
# Bootstrap the host for sqldb-sandbox.
# Idempotent. Re-runnable.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[bootstrap]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root (uses /var/lib and /var/log)"

SANDBOX_USER="sandbox"
SANDBOX_STATE_DIR="/var/lib/sandboxes"
SANDBOX_LOG_DIR="/var/log/sandboxes"
COMPOSE_DIR="${SANDBOX_STATE_DIR}/composes"
TLS_DIR="${SANDBOX_STATE_DIR}/tls"
ENV_FILE="${REPO_ROOT}/.env"
ENV_EXAMPLE="${REPO_ROOT}/.env.example"

log "creating system user '${SANDBOX_USER}'"
if ! id -u "${SANDBOX_USER}" >/dev/null 2>&1; then
  useradd --system --create-home --shell /usr/sbin/nologin "${SANDBOX_USER}"
fi

log "creating directories"
mkdir -p "${COMPOSE_DIR}" "${TLS_DIR}" "${SANDBOX_LOG_DIR}"
chown -R root:"${SANDBOX_USER}" "${COMPOSE_DIR}" "${TLS_DIR}"
chmod 0770 "${COMPOSE_DIR}" "${TLS_DIR}"
chown -R root:"${SANDBOX_USER}" "${SANDBOX_STATE_DIR}"
chmod 0770 "${SANDBOX_STATE_DIR}"
chown -R root:"${SANDBOX_USER}" "${SANDBOX_LOG_DIR}"
chmod 0770 "${SANDBOX_LOG_DIR}"

log "ensuring '${SANDBOX_USER}' is in 'docker' group"
if ! groups "${SANDBOX_USER}" | tr ' ' '\n' | grep -qx docker; then
  usermod -aG docker "${SANDBOX_USER}"
fi

log "checking docker + compose"
command -v docker >/dev/null || die "docker not installed"
docker compose version >/dev/null 2>&1 || die "docker compose v2 plugin not installed"

log "ensuring mysqldump + mysql clients are present"
for bin in mysqldump mysql mysqladmin; do
  if ! command -v "${bin}" >/dev/null 2>&1; then
    warn "${bin} not found; install mysql-client (apt: default-mysql-client, yum: mysql)"
  fi
done

log "preparing SSH directory for prod key"
SSH_DIR="/home/${SANDBOX_USER}/.ssh"
mkdir -p "${SSH_DIR}"
chown "${SANDBOX_USER}":"${SANDBOX_USER}" "${SSH_DIR}"
chmod 0700 "${SSH_DIR}"
KEY_PATH="${SSH_DIR}/sandbox_prod_ed25519"
if [[ ! -f "${KEY_PATH}" ]]; then
  warn "no SSH key at ${KEY_PATH}; generate one and add the public key to the prod bastion"
  warn "    sudo -u ${SANDBOX_USER} ssh-keygen -t ed25519 -f ${KEY_PATH} -N ''"
fi
chmod 0600 "${KEY_PATH}" 2>/dev/null || true

log "preparing .env"
if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${ENV_EXAMPLE}" "${ENV_FILE}"
  chmod 0640 "${ENV_FILE}"
  chown root:"${SANDBOX_USER}" "${ENV_FILE}"
  warn ".env created from .env.example; fill in the placeholders before running"
else
  log ".env already exists; leaving it alone"
fi

log "generating fresh secrets if placeholders remain"
PYTHON_BIN="$(command -v python3)"
SANDBOX_API_KEY_VAL="$(openssl rand -hex 32 2>/dev/null || true)"
SANDBOX_WEBHOOK_SECRET_VAL="$(openssl rand -hex 32 2>/dev/null || true)"
SANDBOX_FERNET_KEY_VAL="$(${PYTHON_BIN} -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' 2>/dev/null || true)"

if [[ -n "${SANDBOX_API_KEY_VAL}" ]]; then
  sed -i "s|^SANDBOX_API_KEY=.*|SANDBOX_API_KEY=${SANDBOX_API_KEY_VAL}|" "${ENV_FILE}"
fi
if [[ -n "${SANDBOX_WEBHOOK_SECRET_VAL}" ]]; then
  sed -i "s|^SANDBOX_WEBHOOK_SECRET=.*|SANDBOX_WEBHOOK_SECRET=${SANDBOX_WEBHOOK_SECRET_VAL}|" "${ENV_FILE}"
fi
if [[ -n "${SANDBOX_FERNET_KEY_VAL}" ]]; then
  sed -i "s|^SANDBOX_FERNET_KEY=.*|SANDBOX_FERNET_KEY=${SANDBOX_FERNET_KEY_VAL}|" "${ENV_FILE}"
fi

chmod 0640 "${ENV_FILE}"
chown root:"${SANDBOX_USER}" "${ENV_FILE}"

log "installing python deps"
${PYTHON_BIN} -m pip install --break-system-packages --ignore-installed -q -r "${REPO_ROOT}/requirements.txt" \
  || die "pip install failed; consider a virtualenv instead of --break-system-packages"

log "running test suite"
( cd "${REPO_ROOT}" && ${PYTHON_BIN} -m pytest -q ) || warn "tests failed; investigate before going live"

log "installing nginx site (if nginx present)"
if command -v nginx >/dev/null 2>&1; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  API_DOMAIN="${SANDBOX_NGINX_SERVER_NAME:-${SANDBOX_PUBLIC_HOST:-}}"
  SSL_CERT="${SANDBOX_NGINX_SSL_CERT:-}"
  SSL_KEY="${SANDBOX_NGINX_SSL_KEY:-}"
  UPSTREAM="${SANDBOX_NGINX_UPSTREAM:-127.0.0.1:8080}"
  if [[ -z "${API_DOMAIN}" || -z "${SSL_CERT}" || -z "${SSL_KEY}" ]]; then
    warn "nginx is installed but SANDBOX_NGINX_* / SANDBOX_PUBLIC_HOST unset; skipping nginx install"
  elif [[ ! -f "${SSL_CERT}" || ! -f "${SSL_KEY}" ]]; then
    warn "TLS cert/key not found at ${SSL_CERT} / ${SSL_KEY}; skipping nginx install"
    warn "Generate one (e.g. 'certbot --nginx -d ${API_DOMAIN}') and re-run bootstrap"
  else
    RENDERED="/etc/nginx/sites-available/sqldb-sandbox.conf"
    sed \
      -e "s|__API_DOMAIN__|${API_DOMAIN}|g" \
      -e "s|__SSL_CERT__|${SSL_CERT}|g" \
      -e "s|__SSL_KEY__|${SSL_KEY}|g" \
      -e "s|__UPSTREAM__|${UPSTREAM}|g" \
      "${REPO_ROOT}/deploy/nginx/sqldb-sandbox.conf" > "${RENDERED}"
    chmod 0644 "${RENDERED}"
    ln -sf "${RENDERED}" /etc/nginx/sites-enabled/sqldb-sandbox.conf
    # Remove the default site if it exists and conflicts on port 80.
    if [[ -f /etc/nginx/sites-enabled/default ]]; then
      rm -f /etc/nginx/sites-enabled/default
      log "removed default nginx site"
    fi
    if nginx -t >/dev/null 2>&1; then
      systemctl reload nginx || warn "systemctl reload nginx failed (is nginx running?)"
      log "nginx site installed: ${RENDERED}"
    else
      warn "nginx config validation failed; run 'nginx -t' to see the error"
    fi
  fi
else
  warn "nginx not installed; skipping nginx site install. Install with: apt install nginx"
fi

log "installing systemd unit (if systemd present)"
if command -v systemctl >/dev/null 2>&1; then
  if [[ -d /etc/systemd/system ]]; then
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    WORKING_DIR="${SANDBOX_WORKING_DIR:-/opt/sqldb-sandbox-setup}"
    if [[ -d "${WORKING_DIR}" ]]; then
      RENDERED_UNIT="/etc/systemd/system/sqldb-sandbox.service"
      sed "s|__WORKING_DIR__|${WORKING_DIR}|g" \
        "${REPO_ROOT}/deploy/systemd/sqldb-sandbox.service" > "${RENDERED_UNIT}"
      chmod 0644 "${RENDERED_UNIT}"
      systemctl daemon-reload
      systemctl enable sqldb-sandbox.service || warn "systemctl enable failed"
      log "systemd unit installed: ${RENDERED_UNIT} (working dir ${WORKING_DIR})"
    else
      warn "SANDBOX_WORKING_DIR=${WORKING_DIR} does not exist; symlink the repo first:"
      warn "    ln -sf ${REPO_ROOT} ${WORKING_DIR}"
    fi
  fi
else
  warn "systemd not present; use scripts/run.sh or your supervisor of choice"
fi

log "installing logrotate config"
if [[ -d /etc/logrotate.d ]]; then
  install -m 0644 "${REPO_ROOT}/deploy/logrotate/sqldb-sandbox" \
    /etc/logrotate.d/sqldb-sandbox
  log "logrotate config installed: /etc/logrotate.d/sqldb-sandbox"
fi

log "state.db backup cron (H7)"
cat <<'EOF'
  Recommend (run once, then add to /etc/cron.d/sqldb-sandbox):
    0 * * * * root /opt/sqldb-sandbox-setup/scripts/backup-state.sh
  Override defaults in .env:
    SANDBOX_BACKUP_DIR=/var/lib/sandboxes/backups
    SANDBOX_BACKUP_RETENTION_HOURS=168
EOF

log "done. next steps:"

log "done. next steps:"
cat <<EOF
  1. Edit ${ENV_FILE} and fill in:
       SANDBOX_MYSQL_HOST=        (host public IP returned to devs for MySQL access)
       PROD_SSH_HOST=             (bastion host)
       PROD_MYSQL_HOST=           (prod MySQL hostname)
       PROD_MYSQL_USER=           (dump-only MySQL user)
       PROD_MYSQL_PASSWORD=       (their password)
       SANDBOX_NGINX_SSL_CERT=    (path; e.g. Let's Encrypt fullchain.pem)
       SANDBOX_NGINX_SSL_KEY=     (path; e.g. Let's Encrypt privkey.pem)

  2. Configure DNS: api-testdb.abc.co.zm -> this host's public IP (Cloudflare
     "DNS only" grey-cloud so nginx terminates TLS).

  3. Make sure TLS cert exists at the SANDBOX_NGINX_SSL_* paths
     (e.g. 'certbot --nginx -d api-testdb.abc.co.zm'), then re-run
     'sudo bash scripts/bootstrap.sh' so nginx picks it up.

  4. Apply the dump-only MySQL grants on prod (see PLAN.md §11 item 9).

  5. Start the API:
       sudo systemctl start sqldb-sandbox   # and: journalctl -u sqldb-sandbox -f
     OR foreground:
       bash scripts/run.sh
EOF